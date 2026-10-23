# TechRecon → plataforma de reconhecimento no navegador

Plano para evoluir a extensão de análise passiva de **uma página** para
reconhecimento ativo de **um site inteiro no escopo autorizado**, superando a
CLI [Web-Application-Reconnaissance-Investigation-Platform](https://github.com/excanear/Web-Application-Reconnaissance-Investigation-Platform)
no que o navegador faz melhor, e sendo honesta onde não a substitui.

## Decisões aprovadas
1. **Crawling ativo no escopo** — a extensão pede host permissions sob demanda e
   percorre o site. Deixa de ser "mínima e passiva".
2. **Dataset Wappalyzer** — ingere o fork webappanalyzer (~7.586 tecnologias) além
   das 140 assinaturas curadas.
3. **Correlação + confirmação não destrutiva + checagens passivas de misconfig** —
   sem motor de exploração.

## Princípios inegociáveis (no código, não só no README)
1. **Autorização e escopo primeiro.** Nenhuma varredura sem escopo declarado e aceite
   de autorização por alvo. Host permissions pedidas em runtime, só para o escopo.
2. **Crawler não destrutivo.** Só segue links GET idempotentes. Pula logout/delete/
   action/nonce/token, mailto/tel, downloads. Nunca submete formulários, nunca repete
   URL, respeita rate limit e concorrência.
3. **Zero exploração.** Sem payloads de ataque. "Confirmada" = verificação manual do
   analista ou checagem segura (versão exata + existência de caminho no escopo).
   Misconfig = só o observável.
4. **Sem invenção.** CVE, versão, score ou resultado: falha de fonte vira erro, nunca
   vazio apresentado como sucesso.

## Arquitetura

A unidade deixa de ser "aba" e passa a ser **ScanSession**, persistida em IndexedDB.

```
popup (lançador + progresso)      dashboard (aba cheia: inventário, mapa, matriz, CVEs)
        └──────────── port ───────────────┘
                        │
              service worker ── ScanEngine (orquestra a sessão)
                        │
 Scope/Auth ─ Crawler ─ Fingerprint(agregado) ─ CVE(NVD/OSV/EPSS/KEV) ─ Misconfig
                        │
                   IndexedDB (sessions, pages, assets, techFindings, cveCache, misconfig)
```

## Fases

| Fase | Entrega |
|---|---|
| **1. Scope & Auth** | Modelo de escopo + matcher, gate de autorização, rate limiter por host + concorrência, classificador de links idempotentes, ScanSession em IndexedDB |
| **2. Crawler** | BFS no escopo reusando `collector.ts`, mapa do site, discovery por CT logs (crt.sh), UI de novo scan + progresso |
| **3. Fingerprint força máxima** | Ingestão Wappalyzer **por download em runtime** (GPL-3.0 não vai no bundle MIT; commit + SHA-256 fixados), curadas com precedência, proveniência `source`, `requires`/`requiresCategory`, versões condicionais |
| **4. CVE em escala** | Correlação única por tecnologia sobre o inventário agregado (cache/limites compartilhados), dedupe entre tecnologias, enriquecimento CISA KEV + EPSS com estado "não verificado" explícito, prioridade KEV → faixa EPSS → CVSS |
| **5. Misconfig passivo** | Headers, cookies, CORS, conteúdo misto, SRI, segredos expostos, arquivos sensíveis — só observável/GET idempotente |
| **6. Dashboard + export** | Aba cheia interativa + export JSON/MD/CSV/HTML |

Cada fase fecha com build + typecheck + testes verdes e commit próprio.

## Supera a CLI em
Crawl autenticado e renderizado; fingerprint agregado do site; CVE multi-fonte
(NVD+OSV+EPSS+KEV vs só NVD); dashboard interativo; zero instalação de ferramentas Go.

## Não substitui a CLI em
Os 4 motores de validação ativa (nuclei/Metasploit/nmap/testssl) — navegador não os
roda. A extensão entrega inventário + priorização que alimenta essa validação.
