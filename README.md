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
| `src/fingerprinting/` | Formato de assinatura (`signature.ts`), motor (`engine.ts`), seleção de versão, 140 assinaturas em `signatures/`, conjunto ativo (`registry.ts`) e conversor/download da base Wappalyzer (`wappalyzer/`) |
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

Tipos de regra: `html`, `scriptSrc`, `script` (inline), `stylesheet`, `meta`, `headers`, `cookies` (por nome), `globals` (caminho pontuado; `prefixo*` para chaves dinâmicas), `dom` (seletor, atributo, texto ou expando no MAIN world), `url` e `resource`. Cada regra tem confiança de 0 a 100, e a confiança da tecnologia é a soma por regra, limitada a 100. Uma regra com confiança 0 (`versionOnly`) só fornece versão e nunca detecta sozinha. `implies` gera tecnologias **inferidas**, sem versão e marcadas como não observadas. `excludes` remove outra detecção apenas quando toda a evidência dela também está explicada por esta. `requires`/`requiresCategories` descartam a detecção quando nada do que ela exige está presente (detectado ou inferido). `tests/signatures.test.ts` valida automaticamente todas as assinaturas.

### Base comunitária Wappalyzer (opcional)

Em **Opções → Base de assinaturas Wappalyzer**, a extensão baixa o dataset
[enthec/webappanalyzer](https://github.com/enthec/webappanalyzer) e amplia a detecção de 140 para
cerca de 7.650 tecnologias (7.510 assinaturas comunitárias + as curadas).

- **Licença:** o dataset é **GPL-3.0** e, por isso, **não acompanha** a extensão (MIT). Ele só é
  baixado quando você pede e fica apenas neste navegador (IndexedDB). Remover a base restaura o conjunto curado.
- **Integridade:** os 27 arquivos vêm de um commit fixado (`WAPPALYZER_COMMIT`) e cada um é
  conferido contra um SHA-256 fixado no código. Qualquer divergência, falha HTTP ou JSON inválido
  aborta a instalação sem gravar nada.
- **Precedência:** as assinaturas curadas sempre vencem. As 137 entradas do dataset que duplicam
  uma tecnologia curada são descartadas, e as referências a elas (`implies`, `requires`,
  `excludes`) passam a apontar para a curada.
- **Proveniência e confiança:** detecções da base aparecem com o selo **WA**, com a fonte no detalhe
  e `source` no JSON/Markdown exportado. Cada regra comunitária contribui com 80% da confiança declarada.
- **Conversão** (`src/fingerprinting/wappalyzer/convert.ts`): `html`, `scriptSrc`, `scripts`
  (inline), `meta`, `headers`, `cookies` (só o nome), `js` (globais), `dom` (presença, atributo,
  texto e propriedade), `url` e `xhr` (recursos). Versões `\1` e condicionais `\1?a:b` são
  preservadas. `dns`, `certIssuer`, `robots`, `css` e `probe` não são observáveis aqui; as cerca de
  200 tecnologias que só têm essas regras entram apenas por inferência.

## Fontes de dados

| Fonte | Uso | Observações |
|---|---|---|
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) (NIST) | Tecnologias com CPE (CMS, servidores, linguagens) | Consulta `virtualMatchString=cpe:2.3:a:vendor:product:versão`. Cada resultado é **revalidado localmente** contra `configurations` (intervalos `versionStart*/versionEnd*`, critérios de versão exata, configurações AND). O que não confere é descartado e contabilizado. A versão corrigida vem de `versionEndExcluding`; quando a fonte só informa `versionEndIncluding`, nenhuma é inventada. |
| [OSV.dev](https://osv.dev) | Bibliotecas JavaScript com pacote npm | Agrega o GitHub Advisory Database (advisories revisados). Os intervalos SEMVER/ECOSYSTEM do **pacote exato** são reavaliados localmente. O score CVSS v3 é calculado a partir do vetor; vetores CVSS v4 são exibidos sem score calculado. |

**Chave de API do NVD (opcional):** sem chave, o NVD permite cerca de 5 requisições a cada 30 s, e a extensão espaça as consultas (6,5 s). Com chave ([solicitar aqui](https://nvd.nist.gov/developers/request-an-api-key)), o limite é de 50 a cada 30 s. A chave é configurada em **Opções**, fica só em `chrome.storage.local` e é enviada apenas no header `apiKey` ao NVD.

**Cache:** só respostas bem-sucedidas são guardadas (TTL configurável de 1 h a 7 dias, padrão 24 h, até 400 consultas). Falhas nunca são cacheadas nem convertidas em resultado vazio. A interface mostra o erro e oferece **Tentar novamente**.

### Inteligência de exploração e prioridade

| Fonte | Uso | Observações |
|---|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVEs com exploração ativa confirmada | Catálogo oficial inteiro (~1,8 MB) baixado de `www.cisa.gov`, reduzido aos campos exibidos e guardado no IndexedDB por 24 h. Consultas são locais. Se a atualização falhar, uma cópia anterior só é usada **com aviso** e a versão do catálogo; sem cópia, o KEV aparece como "não verificado". |
| [FIRST EPSS](https://www.first.org/epss/) | Probabilidade de exploração em 30 dias | Consulta em lote (até 100 CVEs por requisição). CVE sem score publicado aparece como "sem score", nunca como 0%. Percentuais são truncados, nunca arredondados para cima. |

Cada vulnerabilidade distingue três estados por fonte: **listada/pontuada**, **verificada sem
registro** e **não verificada** (fonte indisponível). Uma falha nunca vira "não listada".

**Prioridade:** 1) CISA KEV; 2) faixa EPSS alta (≥ 10%) e média (≥ 1%); 3) CVSS e severidade;
4) score EPSS exato. A faixa de EPSS vem antes do CVSS porque diferenças pequenas de EPSS são
ruído, mas uma CVE realmente provável de ser explorada não deve ficar abaixo de um 9,8 teórico.

**O que é enviado para fora:** apenas `fornecedor:produto:versão` (NVD), `pacote@versão` (OSV) e IDs de CVE (EPSS). URL, HTML, cookies e headers da página nunca saem do navegador. A instalação opcional da base Wappalyzer faz GETs sem credenciais a `raw.githubusercontent.com`, sem enviar nada sobre os alvos.

### Potencial × confirmada

- **Potencial:** a versão observada está dentro de um intervalo afetado segundo a fonte citada. Isso **não** significa que a aplicação seja explorável, porque configuração, backports e mitigações não são verificáveis passivamente. Quando o banner indica pacote de distribuição (ex.: `nginx/1.18.0 (Ubuntu)`), o risco de backport é sinalizado.
- **Confirmada:** marcação manual do analista após verificação, salva por domínio e incluída nas exportações.
- Tecnologias sem versão, com versão imprecisa (ex.: `Drupal 10`), com versões conflitantes ou apenas inferidas **não são correlacionadas**. A aba Vulnerabilidades mostra essa cobertura.

## Varredura do site (crawling autorizado)

Além da análise passiva de uma aba, o ícone **Varredura do site** (radar) abre o modo de
reconhecimento de **site inteiro**:

- Você define a **URL inicial**, uma **declaração de autorização obrigatória**, o teto de
  páginas, a profundidade, a taxa (req/s) e se inclui subdomínios.
- Ao iniciar, a extensão pede **permissão de acesso aos domínios do escopo** (concedida sob
  demanda; o acesso amplo fica em `optional_host_permissions`, não no `host_permissions`).
- O crawler percorre o site **na sua sessão logada** (`fetch` com `credentials: 'include'`),
  então alcança áreas autenticadas. Cada página é lida num **offscreen document** (único lugar
  da extensão com `fetch` + `DOMParser`), e o fingerprint é **agregado por todo o site**.
- Como o crawl usa `fetch`, ele obtém os **headers de resposta de cada página** — algo que a
  análise passiva de uma aba não tem. Em troca, não executa JavaScript, então detecções que
  dependem de variáveis globais em runtime só aparecem na análise da aba ativa.

**Guard-rails (no código, testados):** só segue links **GET idempotentes**; recusa
logout/signout, delete/remove, `?action=`, `?_wpnonce`/`token`, downloads e `mailto:`/`tel:`;
nunca submete formulários; nunca repete uma URL; respeita rate limit por host e concorrência;
os limites são *clampados* a faixas seguras. Uma sessão não inicia sem autorização registrada.

**CVE em escala:** terminado o crawl, cada tecnologia do inventário agregado é correlacionada
**uma vez para o site inteiro** (não uma por página), com o mesmo cache e os mesmos limites de
taxa da análise de página. Só entram tecnologias com mapeamento e versão exata observada; as
demais ficam registradas com o motivo. As vulnerabilidades são **deduplicadas entre
tecnologias** (a mesma CVE via dois produtos, ou um advisory e sua CVE, aparece uma vez, com
todas as tecnologias afetadas), enriquecidas com KEV + EPSS e ordenadas por prioridade. Falhas
de consulta aparecem por tecnologia; nada é presumido. Interromper a varredura nessa fase
mantém o que já foi consultado e marca o resultado como parcial. Com "Consultar
vulnerabilidades" desligado, o scan não faz nenhuma consulta.

**Configuração (passiva):** durante o crawl, cada página HTML obtida é examinada a partir da
resposta que o crawler **já recebeu**, sem nenhuma requisição adicional (um e2e garante que só
são requisitadas páginas linkadas pelo site e os recursos que elas referenciam). Checagens:
página sem HTTPS; HSTS ausente ou fraco; CSP ausente ou permissiva (header ou meta);
`X-Content-Type-Options` ausente; falta de proteção contra framing (X-Frame-Options ou
`frame-ancestors` em header); versão divulgada em `Server`/`X-Powered-By`; CORS `*` (e `*` com
credenciais); conteúdo misto (scripts e CSS via HTTP em página HTTPS); scripts de terceiros sem
SRI. Os achados são agregados por site, com o número de páginas afetadas e exemplos (URLs
redigidas). Atributos de cookies (Secure, HttpOnly, SameSite) **não** são verificados no scan,
porque o navegador não expõe `Set-Cookie` a extensões. Não há busca por arquivos ou caminhos
sensíveis: o scan não requisita nada que o próprio site não linke.

Sessões, inventário, vulnerabilidades e achados de configuração ficam em **IndexedDB**, no perfil do navegador.

## Permissões

| Permissão | Motivo |
|---|---|
| `activeTab` | Acesso temporário apenas à aba em que você clicou no ícone. Sem acesso a outras abas nem ao histórico. |
| `scripting` | Injetar o coletor e as sondas sob demanda, sem content script permanente |
| `storage` | Opções, cache de CVEs, confirmações e resultado da última análise por aba (session) |
| `offscreen` | Documento offscreen que faz fetch + parse das páginas durante a varredura |
| `host_permissions`: `services.nvd.nist.gov`, `api.osv.dev`, `www.cisa.gov` | Consultar as APIs de vulnerabilidade e baixar o catálogo KEV a partir do service worker (o feed da CISA não envia CORS). O EPSS (`api.first.org`) envia CORS aberto e não precisa de permissão. |
| `optional_host_permissions`: `http(s)://*/*` | **Não concedida por padrão.** Pedida em runtime, só para os domínios do escopo, no início de cada varredura. |

Não há `tabs`, `webRequest`, `cookies` nem content scripts declarados. O acesso amplo a hosts é
opcional e só é concedido quando você autoriza uma varredura.

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
