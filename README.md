# TechRecon

Extensão Chrome (Manifest V3) de **reconhecimento de aplicações web** para pentesters éticos.
Identifica as tecnologias de um site, com versão, confiança e evidência, cruza as versões com
vulnerabilidades conhecidas e prioriza o que tem exploração real. Funciona de dois modos:

- **Análise da aba:** clique no ícone e veja o que a página aberta usa. É passiva por padrão:
  nenhuma requisição ao alvo sem ação explícita.
- **Varredura do site:** dentro de um escopo que você declara e autoriza, o crawler percorre o site
  inteiro na sua sessão, agrega as tecnologias de todas as páginas, correlaciona CVEs com CISA KEV
  e EPSS e aponta problemas de configuração observáveis. Os resultados ficam num painel em aba cheia
  e podem ser exportados em HTML, Markdown, JSON e CSV.

Princípios aplicados no código, não só neste texto:

1. **Autorização e escopo primeiro.** Nenhuma varredura começa sem escopo declarado e uma
   declaração de autorização registrada. O acesso aos domínios é pedido em runtime, só para o escopo.
2. **Crawler não destrutivo.** Segue apenas links GET idempotentes, nunca submete formulários e
   nunca requisita algo que o próprio site não linke.
3. **Zero exploração.** Não há payloads de ataque. "Confirmada" significa verificada manualmente
   pelo analista.
4. **Sem invenção.** Uma falha de fonte aparece como erro, nunca como resultado vazio. A correlação
   é feita **por versão, nunca por nome isolado**, e é revalidada localmente contra os intervalos
   da fonte oficial.

O roadmap que levou a esta versão está em [`docs/PLAN.md`](docs/PLAN.md).

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
| `npm run build` | Typecheck (tsc) + build do popup, painel, service worker e offscreen + build do coletor (IIFE) |
| `npm test` | Testes unitários (Vitest): assinaturas, motor, versões, Wappalyzer, CPE/NVD, OSV, CVSS, KEV/EPSS, correlação, escopo, crawler, sessões, configuração, recon e exportações |
| `npm run e2e` | Build de teste + Playwright: carrega a extensão no Chromium, analisa uma página local e faz uma varredura completa de um site local de várias páginas, incluindo painel e exports. As consultas a NVD, OSV, CISA KEV e EPSS são **ao vivo** (precisa de rede) |
| `npm run icons` | Regera os PNGs do ícone a partir do SVG |

> `npm run e2e` gera um `dist/` com permissão extra de host para `127.0.0.1`/`localhost`, porque
> testes automatizados não conseguem clicar no ícone da barra nem responder ao pedido de permissão.
> **Rode `npm run build` antes de carregar ou distribuir a extensão.**
>
> Sem chave de API, o NVD às vezes limita requisições, e o e2e da varredura pode estourar o tempo
> parado em "correlacionando CVEs". Rodar de novo resolve.

## Uso

### Análise da aba

O popup tem três abas:
- **Tecnologias:** agrupadas por categoria, com versão, confiança e as evidências de cada detecção.
- **Vulnerabilidades:** CVEs em ordem de prioridade, com selos KEV e EPSS e a cobertura da correlação.
- **Recon:** headers de segurança, scripts, hosts próprios e de terceiros, cookies legíveis e
  conteúdo misto.

A análise é passiva. O botão **Capturar headers** faz uma única requisição GET same-origin à URL da
aba para ler os headers de resposta, e a opção **Capturar headers automaticamente** faz isso em toda
análise. O ícone de exportar gera o relatório da página em JSON ou Markdown.

### Varredura do site

O ícone **Varredura do site** (radar) abre o formulário de nova varredura:

1. Informe a **URL inicial** e a **declaração de autorização** (obrigatória; por exemplo, o nome do
   contrato ou do ticket).
2. Ajuste o teto de páginas, a profundidade, a taxa (req/s) e se os subdomínios entram no escopo.
3. Clique em **Autorizar e iniciar varredura**. O Chrome pede acesso aos domínios do escopo.

A varredura passa por três etapas: crawl e fingerprint agregado, correlação de CVEs sobre o
inventário e checagens passivas de configuração. O card da sessão mostra o progresso e os totais
(páginas, tecnologias, CVEs, quantas estão no KEV e achados de configuração). **Abrir painel** leva
ao relatório completo em aba cheia.

### Opções

- **Consultar vulnerabilidades:** liga ou desliga todas as consultas a NVD, OSV, KEV e EPSS, na aba
  e na varredura.
- **Capturar headers automaticamente.**
- **Chave de API do NVD** (opcional).
- **Validade do cache de CVEs** (1 h a 7 dias) e limpeza do cache.
- **Base de assinaturas Wappalyzer:** download opcional, ver
  [Base comunitária Wappalyzer](#base-comunitária-wappalyzer-opcional).
- **Tema** claro ou escuro.

## Como funciona

Análise da aba:

```
popup (React) ──port──▶ service worker ──executeScript──▶ página (aba ativa)
                              │   1. content.js (isolated world): HTML, scripts, meta, nomes de cookies, recursos, DOM
                              │   2. sonda MAIN world: variáveis globais de versão (ex.: jQuery.fn.jquery) e expandos de frameworks
                              │   3. [opcional] 1 GET same-origin para ler headers de resposta
                              ├─▶ fingerprinting/engine (puro, determinístico) → tecnologias + evidências
                              ├─▶ recon → headers de segurança, scripts, hosts, cookies
                              └─▶ cve/correlate → OSV (npm) / NVD (CPE) → verificação local → KEV + EPSS → prioridade
```

Varredura do site:

```
popup / painel ──port──▶ service worker (ScanSession em IndexedDB)
                              │   escopo + autorização obrigatória + host permissions sob demanda
                              ├─▶ crawler BFS (só links GET idempotentes no escopo, rate limit, concorrência)
                              │        └─▶ offscreen document: fetch na sessão do usuário + DOMParser → snapshot + headers
                              │   por página: fingerprint + checagens passivas de configuração
                              ├─▶ agregação por site: tecnologias, achados de configuração, hosts
                              └─▶ fase de CVE: 1 consulta por tecnologia → dedupe → KEV + EPSS → prioridade
```

### Estrutura

| Pasta | Conteúdo |
|---|---|
| `src/fingerprinting/` | Formato de assinatura (`signature.ts`), motor (`engine.ts`), seleção de versão, 140 assinaturas curadas em `signatures/`, conjunto ativo (`registry.ts`) e conversor/download da base Wappalyzer (`wappalyzer/`) |
| `src/cve/` | Comparação de versões, CPE e configurações NVD, clientes NVD e OSV, CVSS v3, throttle/retry HTTP, correlação, CISA KEV, EPSS, enriquecimento, prioridade e dedupe (`enrich.ts`) |
| `src/scope/` | Modelo e matcher de escopo, limites (rate limit por host, concorrência), host permissions em runtime |
| `src/crawler/` | Crawler BFS, classificador de links idempotentes, agregação de tecnologias por site |
| `src/offscreen/` | Documento offscreen: fetch das páginas e extração do snapshot |
| `src/scan/` | Sessões de varredura e gate de autorização, runner e fase de CVE (`cvePhase.ts`) |
| `src/misconfig/` | Checagens passivas de configuração por página e agregação por site |
| `src/db/` | Wrapper de IndexedDB e esquema dos stores |
| `src/content/` | Coletor injetado sob demanda e sondas serializadas (MAIN world, headers) |
| `src/background/` | Service worker: análise da aba, canais de varredura e de datasets, inteligência de vulnerabilidades compartilhada (`intel.ts`) |
| `src/recon/` | Headers de segurança, inventário de scripts e hosts, cookies, conteúdo misto |
| `src/storage/` | Configurações, cache de CVEs, análise por aba (session), confirmações do analista |
| `src/export/` | Relatório da aba (`index.ts`: JSON `techrecon.report/v1` e Markdown) e da varredura (`scan.ts`: HTML, Markdown, JSON `techrecon.scan-report/v1` e CSV) |
| `src/shared/` | Sanitização e redação de segredos |
| `src/popup/` | Popup em React (CSS Modules) |
| `src/dashboard/` | Painel da varredura em aba cheia |
| `tests/` | Testes unitários; `tests/fixtures/` contém **respostas reais** gravadas do NVD, OSV, EPSS, CISA KEV e Wappalyzer (ver o README da pasta) |
| `e2e/` | Testes de ponta a ponta com Playwright e o site local de teste |

## Fingerprinting

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

Tipos de regra: `html`, `scriptSrc`, `script` (inline), `stylesheet`, `meta`, `headers`, `cookies`
(por nome), `globals` (caminho pontuado; `prefixo*` para chaves dinâmicas), `dom` (seletor,
atributo, texto ou expando no MAIN world), `url` e `resource`.

- Cada regra tem confiança de 0 a 100, e a confiança da tecnologia é a soma por regra, limitada a 100.
  Uma regra com confiança 0 (`versionOnly`) só fornece versão e nunca detecta sozinha.
- `implies` gera tecnologias **inferidas**, sem versão e marcadas como não observadas.
- `excludes` remove outra detecção apenas quando toda a evidência dela também está explicada por esta.
- `requires`/`requiresCategories` descartam a detecção quando nada do que ela exige está presente
  (detectado ou inferido).
- Versões aceitam a forma condicional `$1?a:b`.

`tests/signatures.test.ts` valida automaticamente todas as assinaturas.

### Base comunitária Wappalyzer (opcional)

Em **Opções → Base de assinaturas Wappalyzer**, a extensão baixa o dataset
[enthec/webappanalyzer](https://github.com/enthec/webappanalyzer) e amplia a detecção de 140 para
cerca de 7.650 tecnologias (7.510 assinaturas comunitárias + as curadas).

- **Licença:** o dataset é **GPL-3.0** e, por isso, **não acompanha** a extensão (MIT). Ele só é
  baixado quando você pede e fica apenas neste navegador (IndexedDB). Remover a base restaura o
  conjunto curado.
- **Integridade:** os 27 arquivos vêm de um commit fixado (`WAPPALYZER_COMMIT`) e cada um é
  conferido contra um SHA-256 fixado no código. Qualquer divergência, falha HTTP ou JSON inválido
  aborta a instalação sem gravar nada.
- **Precedência:** as assinaturas curadas sempre vencem. As 137 entradas do dataset que duplicam
  uma tecnologia curada são descartadas, e as referências a elas (`implies`, `requires`,
  `excludes`) passam a apontar para a curada.
- **Proveniência e confiança:** detecções da base aparecem com o selo **WA**, com a fonte no
  detalhe e `source` nos exports. Cada regra comunitária contribui com 80% da confiança declarada.
- **Conversão** (`src/fingerprinting/wappalyzer/convert.ts`): `html`, `scriptSrc`, `scripts`
  (inline), `meta`, `headers`, `cookies` (só o nome), `js` (globais), `dom` (presença, atributo,
  texto e propriedade), `url` e `xhr` (recursos). Versões `\1` e condicionais `\1?a:b` são
  preservadas. `dns`, `certIssuer`, `robots`, `css` e `probe` não são observáveis aqui; as cerca de
  200 tecnologias que só têm essas regras entram apenas por inferência.

## Vulnerabilidades

### Fontes de correlação

| Fonte | Uso | Observações |
|---|---|---|
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) (NIST) | Tecnologias com CPE (CMS, servidores, linguagens) | Consulta `virtualMatchString=cpe:2.3:a:vendor:product:versão`. Cada resultado é **revalidado localmente** contra `configurations` (intervalos `versionStart*/versionEnd*`, critérios de versão exata, configurações AND). O que não confere é descartado e contabilizado. A versão corrigida vem de `versionEndExcluding`; quando a fonte só informa `versionEndIncluding`, nenhuma é inventada. |
| [OSV.dev](https://osv.dev) | Bibliotecas JavaScript com pacote npm | Agrega o GitHub Advisory Database (advisories revisados). Os intervalos SEMVER/ECOSYSTEM do **pacote exato** são reavaliados localmente. O score CVSS v3 é calculado a partir do vetor; vetores CVSS v4 são exibidos sem score calculado. |

**Chave de API do NVD (opcional):** sem chave, o NVD permite cerca de 5 requisições a cada 30 s, e a
extensão espaça as consultas (6,5 s). Com chave
([solicitar aqui](https://nvd.nist.gov/developers/request-an-api-key)), o limite é de 50 a cada 30 s.
A chave é configurada em **Opções**, fica só em `chrome.storage.local` e é enviada apenas no header
`apiKey` ao NVD. Recomendada para varreduras, que consultam muitas tecnologias.

**Cache e limites compartilhados:** só respostas bem-sucedidas são guardadas (TTL configurável de
1 h a 7 dias, padrão 24 h, até 400 consultas). Falhas nunca são cacheadas nem convertidas em
resultado vazio; a interface mostra o erro e oferece **Tentar novamente**. A análise da aba e a
varredura usam o mesmo cache e os mesmos limites de taxa, então rodar as duas ao mesmo tempo não
estoura a cota do NVD.

### Inteligência de exploração

| Fonte | Uso | Observações |
|---|---|---|
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVEs com exploração ativa confirmada | Catálogo oficial inteiro (~1,8 MB) baixado de `www.cisa.gov`, reduzido aos campos exibidos e guardado no IndexedDB por 24 h. Consultas são locais. Se a atualização falhar, uma cópia anterior só é usada **com aviso** e a versão do catálogo; sem cópia, o KEV aparece como "não verificado". |
| [FIRST EPSS](https://www.first.org/epss/) | Probabilidade de exploração em 30 dias | Consulta em lote (até 100 CVEs por requisição). CVE sem score publicado aparece como "sem score", nunca como 0%. Percentuais são truncados, nunca arredondados para cima. |

Cada vulnerabilidade distingue três estados por fonte: **listada/pontuada**, **verificada sem
registro** e **não verificada** (fonte indisponível). Uma falha nunca vira "não listada".

### Prioridade

1. Listada no CISA KEV.
2. Faixa EPSS: alta (≥ 10%), depois média (≥ 1%).
3. CVSS e severidade.
4. Score EPSS exato.

A faixa de EPSS vem antes do CVSS porque diferenças pequenas de EPSS são ruído, mas uma CVE
realmente provável de ser explorada não deve ficar abaixo de um 9,8 teórico. A mesma ordem vale no
popup, no painel e nos exports.

### Potencial × confirmada

- **Potencial:** a versão observada está dentro de um intervalo afetado segundo a fonte citada.
  Isso **não** significa que a aplicação seja explorável, porque configuração, backports e
  mitigações não são verificáveis passivamente. Quando o banner indica pacote de distribuição
  (ex.: `nginx/1.18.0 (Ubuntu)`), o risco de backport é sinalizado.
- **Confirmada:** marcação manual do analista após verificação, salva por domínio e incluída nas
  exportações da aba.
- Tecnologias sem versão, com versão imprecisa (ex.: `Drupal 10`), com versões conflitantes ou
  apenas inferidas **não são correlacionadas**. A cobertura aparece na aba Vulnerabilidades e, na
  varredura, por tecnologia.

### O que é enviado para fora

Apenas `fornecedor:produto:versão` (NVD), `pacote@versão` (OSV) e IDs de CVE (EPSS). O catálogo
KEV é baixado inteiro, sem enviar nada. URL, HTML, cookies e headers da página nunca saem do
navegador. A instalação opcional da base Wappalyzer faz GETs sem credenciais a
`raw.githubusercontent.com`, também sem enviar nada sobre os alvos.

## Varredura do site em detalhe

### Crawl

- O crawler percorre o site **na sua sessão logada** (`fetch` com `credentials: 'include'`), então
  alcança áreas autenticadas. Cada página é lida num **offscreen document** (único lugar da extensão
  com `fetch` + `DOMParser`), e o fingerprint é **agregado por todo o site**: cada tecnologia fica com
  a evidência mais forte, a versão exata mais bem sustentada, o número de páginas e exemplos.
- Como o crawl usa `fetch`, ele obtém os **headers de resposta de cada página**, que a análise
  passiva da aba não tem. Em troca, não executa JavaScript, então detecções que dependem de
  variáveis globais em runtime só aparecem na análise da aba ativa.
- O acesso aos domínios do escopo é pedido no início da varredura (o acesso amplo fica em
  `optional_host_permissions`, não em `host_permissions`).

**Guard-rails (no código, testados):** só segue links **GET idempotentes**; recusa logout/signout,
delete/remove, `?action=`, `?_wpnonce`/`token`, downloads e `mailto:`/`tel:`; nunca submete
formulários; nunca repete uma URL; respeita rate limit por host e concorrência; os limites são
*clampados* a faixas seguras. Uma sessão não inicia sem autorização registrada. O e2e verifica que
`/logout` nunca é seguido e que nada fora dos links do site é requisitado.

### CVE em escala

Terminado o crawl, cada tecnologia do inventário agregado é correlacionada **uma vez para o site
inteiro**, não uma vez por página. Só entram tecnologias com mapeamento e versão exata observada;
as demais ficam registradas com o motivo.

- **Dedupe:** a mesma CVE vinda de dois produtos, ou um advisory e sua CVE, aparece uma vez, com
  todas as tecnologias afetadas.
- **Enriquecimento:** KEV + EPSS, e a lista é ordenada por prioridade.
- **Falhas:** aparecem por tecnologia; nada é presumido.
- **Interrupção:** parar a varredura nessa fase mantém o que já foi consultado e marca o resultado
  como parcial.
- Com "Consultar vulnerabilidades" desligado, a varredura não faz nenhuma consulta.

### Configuração (passiva)

Durante o crawl, cada página HTML é examinada a partir da resposta que o crawler **já recebeu**,
sem nenhuma requisição adicional. Checagens:

- página sem HTTPS;
- HSTS ausente ou fraco;
- CSP ausente ou permissiva (header ou meta);
- `X-Content-Type-Options` ausente;
- falta de proteção contra framing (`X-Frame-Options` ou `frame-ancestors` em header);
- versão divulgada em `Server` / `X-Powered-By`;
- CORS `*`, sozinho ou com credenciais;
- conteúdo misto (scripts e CSS via HTTP em página HTTPS);
- scripts de terceiros sem SRI.

Os achados são agregados por site, com o número de páginas afetadas e exemplos (URLs redigidas).

Ficam de fora por decisão: atributos de cookies (Secure, HttpOnly, SameSite), porque o navegador não
expõe `Set-Cookie` a extensões; e qualquer busca por segredos, arquivos ou caminhos sensíveis, porque
a varredura não requisita nada que o próprio site não linke.

### Armazenamento

Sessões, páginas, inventário, vulnerabilidades, achados de configuração, o catálogo KEV e a base
Wappalyzer ficam em **IndexedDB**, no perfil do navegador. Excluir uma varredura apaga todos os
registros dela.

## Painel e export da varredura

**Abrir painel**, no card de cada varredura, abre `dashboard.html` numa aba cheia. O painel mostra a
sessão (escopo, autorização registrada, status ao vivo), os indicadores principais e as abas:

- **Vulnerabilidades:** lista completa priorizada, com busca, filtros de severidade e de tecnologia,
  "Somente CISA KEV" e detalhe expansível (KEV, EPSS, faixas afetadas, base da correspondência,
  referências);
- **Configuração**, **Tecnologias**, **Páginas** e **Hosts**.

Exports, todos gerados localmente a partir dos dados da sessão:

| Formato | Conteúdo |
|---|---|
| Relatório HTML | Arquivo único e estático: sem nenhum script, com CSP `default-src 'none'`, todo texto escapado e só links `http(s)`. Pode ser aberto e compartilhado com segurança. Segue o tema claro/escuro do sistema. |
| Markdown | Resumo, vulnerabilidades priorizadas, falhas de consulta, configuração, tecnologias e páginas |
| JSON | `techrecon.scan-report/v1`, completo (inclui `kev`/`epss` com os estados `null` e ausente) |
| CSV | Uma tabela por arquivo (vulnerabilidades, tecnologias, configuração, páginas), UTF-8 com BOM. Células que começam com `= + - @` são neutralizadas contra injeção de fórmulas em planilhas. |

Em todos os formatos, as URLs passam pela redação de tokens e sessões usada no resto da extensão, e
a declaração de autorização vai junto, para fins de auditoria.

## Permissões

| Permissão | Motivo |
|---|---|
| `activeTab` | Acesso temporário apenas à aba em que você clicou no ícone. Sem acesso a outras abas nem ao histórico. |
| `scripting` | Injetar o coletor e as sondas sob demanda, sem content script permanente |
| `storage` | Opções, cache de CVEs, confirmações e resultado da última análise por aba (session) |
| `offscreen` | Documento offscreen que faz fetch + parse das páginas durante a varredura |
| `host_permissions`: `services.nvd.nist.gov`, `api.osv.dev`, `www.cisa.gov` | Consultar as APIs de vulnerabilidade e baixar o catálogo KEV a partir do service worker (o feed da CISA não envia CORS). O EPSS (`api.first.org`) e o download da base Wappalyzer (`raw.githubusercontent.com`) enviam CORS aberto e não precisam de permissão. |
| `optional_host_permissions`: `http(s)://*/*` | **Não concedida por padrão.** Pedida em runtime, só para os domínios do escopo, no início de cada varredura. |

Não há `tabs`, `webRequest`, `cookies` nem content scripts declarados. O acesso amplo a hosts é
opcional e só é concedido quando você autoriza uma varredura.

## Limitações conhecidas

- **Headers de resposta** não ficam disponíveis passivamente para extensões sem `webRequest` e
  acesso amplo a hosts. Na aba, **Capturar headers** faz **uma** requisição GET same-origin à URL
  (equivalente a recarregar) e lê os headers, abortando antes do corpo; a resposta pode diferir da
  navegação original (cache/CDN). Sem ela, servidores, CDNs e WAFs detectáveis só por headers não
  aparecem, e a ausência de headers de segurança é mostrada como "não observado", não como
  "ausente". A varredura não tem essa limitação, porque obtém os headers de cada página.
- **Cookies:** atributos (Secure, SameSite) e cookies HttpOnly não são observáveis, porque
  `Set-Cookie` nunca é exposto a scripts. Na aba, são listados apenas os nomes (e o tamanho do
  valor) dos cookies legíveis por `document.cookie`. No crawl, nomes de cookies não são observáveis.
- **O crawl não executa JavaScript:** SPAs que montam a navegação no cliente expõem poucos links, e
  detecções por variáveis globais só aparecem na análise da aba.
- **Varreduras e o NVD:** sem chave de API, a fase de CVE de um site com muitas tecnologias leva
  minutos (cerca de 6,5 s por consulta) e pode sofrer limitação de requisições.
- **Páginas protegidas** (`chrome://`, Chrome Web Store, `file://`, visualizador de PDF) não podem
  ser analisadas por extensões.
- Apenas o **frame principal** é analisado; iframes de outras origens não são inspecionados.
- Detecção baseada em assinaturas: tecnologias sem marcadores públicos (ou com marcadores
  removidos/ofuscados) não são detectadas, e banners podem ser falsificados pelo servidor.
- Versões obtidas de nomes de arquivo ou parâmetros `?ver=` podem não refletir o código realmente
  servido. Em caso de conflito, a tecnologia aparece como "versão incerta" e não é correlacionada.
- O agrupamento próprio/terceiro usa uma heurística de domínio registrável (sem a Public Suffix List
  completa).
- CVSS v4 é exibido como vetor e severidade declarada, sem cálculo de score.
- **Não substitui** ferramentas de validação ativa (nuclei, Metasploit, nmap, testssl): o TechRecon
  entrega inventário e priorização para orientar essa validação.
- Interface em português (pt-BR).

## Segurança e privacidade

- Texto externo (página, NVD, OSV, KEV, Wappalyzer) é sanitizado e renderizado como texto pelo
  React. Não há `dangerouslySetInnerHTML`.
- Links passam por validação `http(s)` e IDs de advisory por uma charset estrita.
- Segredos são redigidos antes de serem guardados ou exportados: parâmetros de URL com nomes
  sensíveis, JWTs/strings opacas longas e headers como `Authorization`/`Set-Cookie`/CSRF.
- Dados baixados em runtime são tratados como não confiáveis: a base Wappalyzer tem integridade
  SHA-256 verificada e cada campo e padrão é validado antes do uso; o catálogo KEV e as respostas do
  EPSS são validados campo a campo.
- Exports da varredura: HTML sem scripts e com CSP restritiva, CSV protegido contra injeção de
  fórmulas, Markdown com células escapadas.
- CSP das páginas da extensão: `script-src 'self'; object-src 'none'`. As fontes estão embutidas no
  pacote.
- Tudo o que a extensão guarda fica no perfil do navegador (`chrome.storage` e IndexedDB).

## Testes

- **Unitários** (`npm test`, Vitest): 333 testes. As fixtures são **respostas reais** gravadas do
  NVD, OSV, FIRST EPSS, CISA KEV e Wappalyzer, nunca escritas à mão (ver
  [`tests/fixtures/README.md`](tests/fixtures/README.md)).
- **Ponta a ponta** (`npm run e2e`, Playwright): 4 testes com a extensão real no Chromium. Cobrem a
  análise de uma página (tecnologias, CVEs com KEV/EPSS ao vivo, confirmação do analista, exports,
  recon e captura de headers) e a varredura completa de um site local (crawl, guard-rails, CVEs,
  configuração, painel e exports).

## Licença

O código do TechRecon é distribuído sob a licença **MIT** (declarada em `package.json`).

A base Wappalyzer ([enthec/webappanalyzer](https://github.com/enthec/webappanalyzer)) é **GPL-3.0** e
não faz parte da extensão: ela só é baixada se o usuário optar por isso. A pasta
`tests/fixtures/wappalyzer/` contém um pequeno trecho verbatim dessa base, usado apenas pelos
testes, e está sob GPL-3.0, como indicado no README da pasta.
