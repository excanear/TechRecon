# TechRecon

Extensão Chrome (Manifest V3) de **fingerprinting de tecnologias e inteligência de CVEs** para pentesters éticos. Clique no ícone e o popup mostra o que a página usa, com versão, confiança e evidência, além das vulnerabilidades cuja faixa de versões afetadas contém a versão observada.

- Análise **passiva por padrão**: nenhuma requisição ao alvo sem ação explícita.
- Correlação **por versão, nunca por nome isolado**, verificada localmente contra os intervalos da fonte oficial.
- Resultados **explicáveis** (cada detecção mostra a evidência) e **exportáveis** (JSON e Markdown).

## Instalação e build

Requisitos: Node.js 20+ e Chrome/Chromium 116+.

```bash
npm install
npm run build        # typecheck + build → dist/
```

### Carregar no navegador

1. Abra `chrome://extensions`.
2. Ative o **Modo do desenvolvedor**.
3. Clique em **Carregar sem compactação** e selecione a pasta `dist/`.
4. Abra um site http(s) e clique no ícone do TechRecon, ou use o atalho `Alt+Shift+T`.

Depois de mudar o código, rode `npm run build` e clique em ↻ no card da extensão.

### Scripts

| Comando | O que faz |
|---|---|
| `npm run build` | Typecheck (tsc) + build do popup/service worker + build do coletor (IIFE) |
| `npm test` | Testes unitários (Vitest): regras, motor, versões, CPE/NVD, OSV, CVSS, correlação, recon, exportação |
| `npm run e2e` | Build de teste + Playwright: carrega a extensão no Chromium e percorre o popup contra uma página local, com as APIs reais NVD/OSV (precisa de rede) |
| `npm run icons` | Regera os PNGs do ícone a partir do SVG |

> `npm run e2e` gera um `dist/` com permissão extra de host para `127.0.0.1`/`localhost`, porque testes automatizados não conseguem clicar no ícone da barra para conceder `activeTab`. **Rode `npm run build` antes de carregar ou distribuir a extensão.**

## Como funciona

```
popup (React) ──port──▶ service worker ──executeScript──▶ página (aba ativa)
                              │   1. content.js (isolated world): HTML, scripts, meta, nomes de cookies, recursos, DOM
                              │   2. sonda MAIN world: variáveis globais de versão (ex.: jQuery.fn.jquery) e expandos de frameworks
                              │   3. [opcional] 1 GET same-origin para ler headers de resposta
                              ├─▶ fingerprinting/engine (puro, determinístico) → tecnologias + evidências
                              ├─▶ recon → headers de segurança, scripts, hosts, cookies
                              └─▶ cve/correlate → OSV (pacotes npm) / NVD (CPE) → verificação local de intervalos → cache
```

### Estrutura

| Pasta | Conteúdo |
|---|---|
| `src/fingerprinting/` | Formato de assinatura (`signature.ts`), motor (`engine.ts`), seleção de versão, 140 assinaturas em `signatures/` |
| `src/cve/` | Comparação de versões, parser de CPE e avaliação de configurações NVD, cliente NVD, cliente OSV, calculadora CVSS v3, throttle/retry HTTP, correlação |
| `src/content/` | Coletor injetado sob demanda e sondas serializadas (MAIN world, headers) |
| `src/background/` | Service worker: coordenação, streaming de progresso, badge, páginas não suportadas |
| `src/recon/` | Headers de segurança, inventário de scripts/hosts, cookies, conteúdo misto |
| `src/storage/` | Configurações, cache de CVEs, análise por aba (session), confirmações do analista |
| `src/export/` | Relatórios JSON (`techrecon.report/v1`) e Markdown |
| `src/shared/` | Sanitização e redação de segredos |
| `src/popup/` | Interface React (CSS Modules) |
| `tests/` | Testes unitários; `tests/fixtures/` contém **respostas reais** gravadas do NVD e do OSV |
| `e2e/` | Teste de ponta a ponta com Playwright |

### Adicionar uma assinatura

Edite o arquivo adequado em `src/fingerprinting/signatures/`:

```ts
{
  id: 'example',
  name: 'Example.js',
  categories: ['js-library'],
  website: 'https://example.org',
  npm: 'example',                 // habilita correlação via OSV
  // cpe: ['vendor:product'],     // ou via NVD
  rules: {
    globals: { 'Example.version': [r(VERSION_VALUE, { version: '$1' })] },
    scriptSrc: [r(/\/example@(\d+(?:\.\d+)+)\//, { version: '$1' }), r(/\/example(?:\.min)?\.js/, { confidence: 50 })],
  },
}
```

Tipos de regra: `html`, `scriptSrc`, `script` (inline), `stylesheet`, `meta`, `headers`, `cookies` (por nome), `globals` (caminho pontuado; `prefixo*` para chaves dinâmicas), `dom` (seletor, atributo, texto ou expando no MAIN world), `url` e `resource`. Cada regra tem confiança de 0 a 100, e a confiança da tecnologia é a soma por regra, limitada a 100. Uma regra com confiança 0 (`versionOnly`) só fornece versão e nunca detecta sozinha. `implies` gera tecnologias **inferidas**, sem versão e marcadas como não observadas. `excludes` remove outra detecção apenas quando toda a evidência dela também está explicada por esta. `tests/signatures.test.ts` valida automaticamente todas as assinaturas.

## Fontes de dados

| Fonte | Uso | Observações |
|---|---|---|
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) (NIST) | Tecnologias com CPE (CMS, servidores, linguagens) | Consulta `virtualMatchString=cpe:2.3:a:vendor:product:versão`. Cada resultado é **revalidado localmente** contra `configurations` (intervalos `versionStart*/versionEnd*`, critérios de versão exata, configurações AND). O que não confere é descartado e contabilizado. A versão corrigida vem de `versionEndExcluding`; quando a fonte só informa `versionEndIncluding`, nenhuma é inventada. |
| [OSV.dev](https://osv.dev) | Bibliotecas JavaScript com pacote npm | Agrega o GitHub Advisory Database (advisories revisados). Os intervalos SEMVER/ECOSYSTEM do **pacote exato** são reavaliados localmente. O score CVSS v3 é calculado a partir do vetor; vetores CVSS v4 são exibidos sem score calculado. |

**Chave de API do NVD (opcional):** sem chave, o NVD permite cerca de 5 requisições a cada 30 s, e a extensão espaça as consultas (6,5 s). Com chave ([solicitar aqui](https://nvd.nist.gov/developers/request-an-api-key)), o limite é de 50 a cada 30 s. A chave é configurada em **Opções**, fica só em `chrome.storage.local` e é enviada apenas no header `apiKey` ao NVD.

**Cache:** só respostas bem-sucedidas são guardadas (TTL configurável de 1 h a 7 dias, padrão 24 h, até 400 consultas). Falhas nunca são cacheadas nem convertidas em resultado vazio. A interface mostra o erro e oferece **Tentar novamente**.

**O que é enviado para fora:** apenas `fornecedor:produto:versão` (NVD) ou `pacote@versão` (OSV). URL, HTML, cookies e headers da página nunca saem do navegador.

### Potencial × confirmada

- **Potencial:** a versão observada está dentro de um intervalo afetado segundo a fonte citada. Isso **não** significa que a aplicação seja explorável, porque configuração, backports e mitigações não são verificáveis passivamente. Quando o banner indica pacote de distribuição (ex.: `nginx/1.18.0 (Ubuntu)`), o risco de backport é sinalizado.
- **Confirmada:** marcação manual do analista após verificação, salva por domínio e incluída nas exportações.
- Tecnologias sem versão, com versão imprecisa (ex.: `Drupal 10`), com versões conflitantes ou apenas inferidas **não são correlacionadas**. A aba Vulnerabilidades mostra essa cobertura.

## Permissões

| Permissão | Motivo |
|---|---|
| `activeTab` | Acesso temporário apenas à aba em que você clicou no ícone. Sem acesso a outras abas nem ao histórico. |
| `scripting` | Injetar o coletor e as sondas sob demanda, sem content script permanente |
| `storage` | Opções, cache de CVEs, confirmações e resultado da última análise por aba (session) |
| `host_permissions`: `services.nvd.nist.gov`, `api.osv.dev` | Consultar as APIs de vulnerabilidade a partir do service worker (CORS) |

Não há `tabs`, `webRequest`, `cookies`, `<all_urls>` nem content scripts declarados.

## Limitações conhecidas

- **Headers de resposta** não ficam disponíveis passivamente para extensões sem `webRequest` e acesso amplo a hosts. A opção **Capturar headers** faz **uma** requisição GET same-origin à URL da aba (equivalente a recarregar) e lê os headers, abortando antes do corpo. A resposta pode diferir da navegação original (cache/CDN). Sem ela, servidores, CDNs e WAFs detectáveis só por headers não aparecem, e a ausência de headers de segurança é mostrada como "não observado", não como "ausente".
- **Atributos de cookies** (Secure, SameSite) e **cookies HttpOnly** não são observáveis. `Set-Cookie` nunca é exposto a scripts. São listados apenas os nomes (e o tamanho do valor) dos cookies legíveis por `document.cookie`, que por definição não têm HttpOnly.
- **Páginas protegidas** (`chrome://`, Chrome Web Store, `file://`, visualizador de PDF) não podem ser analisadas por extensões.
- Apenas o **frame principal** é analisado. iframes de outras origens não são inspecionados.
- Detecção baseada em assinaturas: tecnologias sem marcadores públicos (ou com marcadores removidos/ofuscados) não são detectadas, e banners podem ser falsificados pelo servidor.
- Versões obtidas de nomes de arquivo ou parâmetros `?ver=` podem não refletir o código realmente servido. Em caso de conflito, a tecnologia aparece como "versão incerta" e não é correlacionada.
- O agrupamento próprio/terceiro usa uma heurística de domínio registrável (sem a Public Suffix List completa).
- CVSS v4 é exibido como vetor e severidade declarada, sem cálculo de score.
- Interface em português (pt-BR).

## Segurança e privacidade

- Texto externo (página, NVD, OSV) é sanitizado e renderizado como texto pelo React. Não há `dangerouslySetInnerHTML`.
- Links passam por validação `http(s)` e IDs de advisory por uma charset estrita.
- Segredos são redigidos antes de serem guardados ou exportados: parâmetros de URL com nomes sensíveis, JWTs/strings opacas longas e headers como `Authorization`/`Set-Cookie`/CSRF.
- CSP das páginas da extensão: `script-src 'self'; object-src 'none'`. As fontes estão embutidas no pacote.
