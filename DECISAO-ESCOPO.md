# DECISAO-ESCOPO — MCP Server `calixto-secret-scanner`

Atividade: PDA, Semana 4 — MCP na prática (Módulo 2). Autor: MCP Arquiteto.
Convenção: cada afirmação é marcada como **[FATO]** (observado no código ou no repositório), **[HIPÓTESE]** (não verificado por teste) ou **[DECISÃO]** (escolha de projeto).

---

## 1. Contexto do projeto

- **Projeto:** Calixto AI, aplicativo desktop (Windows) em que vários agentes de IA rodam em terminais reais num canvas. **[FATO]** (`AGENTS.md`, `package.json` raiz: monorepo pnpm `calixto-ai`).
- **Repositório / branch:** repositório do app Calixto AI (branch `feat/mcp-secret-scanner`); este repositório contém só o servidor, com uma cópia de `redaction.ts` em `meu-mcp-server/src/`, criado a partir do commit `e367989`. A pasta do repositório mantém o nome antigo de propósito. **[FATO]**
- **Stack:** Node ≥ 24.14, TypeScript (`strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`), `vitest`, `zod`. O servidor MCP é um pacote npm independente em `meu-mcp-server/`, usando `@modelcontextprotocol/sdk` 1.32.2 e `zod` 4.6.7 (versões fixadas). **[FATO]** (`meu-mcp-server/package.json`)
- **Funcionalidade reaproveitada:** `packages/core/src/redaction.ts`, módulo que já impede que chaves de API e tokens apareçam em logs, erros e respostas ao renderer. **[FATO]**
- **Problema real identificado:** o Calixto já sabe *mascarar* segredos numa string (`redactString`), mas um agente não tem como perguntar "este arquivo do workspace contém segredos, e onde?". Hoje isso exigiria ler o arquivo inteiro, o que expõe o segredo ao modelo. **[DECISÃO]** (formulação do problema; o módulo `redaction.ts` e a ausência dessa consulta são **[FATO]**)

### Alteração no código existente

Para expor os padrões sem expor o texto casado, `redaction.ts` foi alterado no worktree: os padrões ganharam nome (`NAMED_SECRET_PATTERNS`) e foi adicionada `detectSecrets(input)`, que devolve `{ kind, count }[]` e nunca o texto casado. `SECRET_PATTERNS` continua existindo, derivado da lista nomeada, então o comportamento de `redactString` não deveria mudar. **[FATO]** (o diff existe, `git status` mostra `M packages/core/src/redaction.ts`). Que `redactString` continua idêntico não foi verificado por mim: o orquestrador relata a suíte do core com 11 arquivos ok, e `packages/core/test/redaction.test.ts` tem um teste "agrees with redactString" (seção 8).

---

## 2. Tool MCP selecionada

- **Nome:** `scan_file_for_secrets` (servidor `calixto-secret-scanner`, versão `1.0.0`). **[FATO]** (`server.ts`)
- **Descrição (a que o modelo vê):** relata quais linhas de um arquivo de texto dentro da raiz permitida contêm chaves de API, bearer tokens ou campos de credencial, usando as regras de redação do Calixto; devolve só número de linha e tipo, nunca o segredo; o conteúdo do arquivo é dado não confiável. **[FATO]**
- **Anotações MCP:** `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false`. **[FATO]**
- **Justificativa:** uma única tool com responsabilidade bem definida, entrada tipada, saída verificável e limites claros, sem exigir escrita, rede nem execução de comandos. Resolve o problema da seção 1 sem entregar o segredo ao modelo. **[DECISÃO]**
- **Funcionalidade reaproveitada:** `detectSecrets` em `packages/core/src/redaction.ts`. **[FATO]**

---

## 3. Contrato da tool

### Entrada

| Campo | Tipo | Obrigatório | Limite |
|---|---|---|---|
| `path` | string | sim | 1 a 260 caracteres; relativo à raiz permitida; sem caracteres de controle nem `< > : " \| ? *`; sem segmento `..`; não absoluto (Windows ou POSIX); sem segmento terminado em `.` ou espaço |
| `maxFindings` | inteiro | não (padrão 50) | 1 a 100 |

**[FATO]** (schema Zod em `server.ts` e validação repetida em `validateInput`, `scanner.ts`). A validação é feita duas vezes de propósito: pelo SDK e de novo no handler. **[DECISÃO]**

A raiz permitida vem da variável de ambiente `CALIXTO_MCP_ROOT`; sem ela, usa o diretório de trabalho do processo. A raiz é resolvida uma vez na partida com `realpath`. **[FATO]** (`index.ts`, `resolveRoot`)

### Saída (sucesso)

Formato: `structuredContent` com o mesmo JSON também em `content[0].text`. **[FATO]**

| Campo | Significado |
|---|---|
| `file` | caminho relativo normalizado com `/` (nunca absoluto) |
| `bytesScanned` | bytes lidos |
| `linesScanned` | linhas analisadas |
| `findingsCount` | total de achados, inclusive os além de `maxFindings` |
| `truncated` | `true` se `findingsCount` > achados listados |
| `findings[]` | `{ line, kind, count }`, no máximo `maxFindings` itens |

`kind` é um destes rótulos fixos: `sk-key`, `bearer-token`, `github-token`, `google-api-key`, `anthropic-key`, `xai-key`, `deepseek-key`, `json-credential`. O trecho do segredo **nunca** faz parte da saída. **[FATO]**

### Erros esperados

O servidor tem **8 códigos de erro** (`ErrorCode` em `scanner.ts`). A resposta de erro tem `isError: true` e o corpo `{"error":{"code","message"}}`. A mensagem é fixa por código e não repete a entrada nem caminhos absolutos. **[FATO]**

| Código | Quando |
|---|---|
| `E_VALIDATION` | tipo errado, vazio, longo demais, caractere inválido, `maxFindings` fora de 1–100, segmento terminado em `.`/espaço, alvo que não é arquivo regular |
| `E_OUTSIDE_ROOT` | caminho absoluto, segmento `..`, ou o caminho real (após symlinks) cai fora da raiz |
| `E_DENIED` | nome ou segmento proibido (seção 4), ou arquivo com mais de um hardlink (`nlink > 1`) |
| `E_NOT_FOUND` | não existe ou não pôde ser aberto |
| `E_TOO_LARGE` | arquivo > 1 MiB, ou > 20 000 linhas |
| `E_BINARY` | byte `0x00` nos primeiros 8 KiB |
| `E_TIMEOUT` | prazo de 5 s excedido (verificado a cada 1000 linhas) |
| `E_INTERNAL` | qualquer outra falha; só registra uma linha genérica no stderr |

---

## 4. Limites de escopo

### O que faz

- Lê **um** arquivo de texto por chamada, dentro da raiz permitida, somente leitura.
- Aplica `detectSecrets` linha a linha e devolve número da linha, tipo e contagem.

### O que não faz

- Não devolve o conteúdo do arquivo nem o segredo, nem em trecho mascarado.
- Não lista diretórios, não varre pastas, não escreve, não apaga, não executa comandos, não usa rede. **[FATO]** (o código só importa `fs/promises`, `fs.constants` e `path`)
- Não detecta segredos fora dos 8 padrões atuais (por exemplo, chaves da AWS ou blocos de chave privada). **[FATO]**
- Não detecta segredo dividido em duas linhas, porque cada linha é analisada isoladamente. **[FATO]**
- Não lê arquivos de segredo conhecidos: qualquer nome que **comece** com `.env` (regra `/^\.env/i`: bloqueia `.env`, `.env.local`, `.envrc`, `.env-prod`), `*.pem`, `*.key`, `*.pfx`, `*.p12`, `*.kdbx`, `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519*`, `credentials*`; segmentos `.git` e `node_modules`; nomes de dispositivo do Windows (`CON`, `PRN`, `AUX`, `NUL`, `COM0-9`, `LPT0-9`, com ou sem extensão). **[FATO]**
- Não lê arquivo com mais de um hardlink (`nlink > 1`): `E_DENIED`. A checagem é feita no arquivo já aberto. **[FATO]**

---

## 5. Arquitetura, fluxo e fronteiras de confiança

### Arquitetura **[FATO]**

```
Claude Code (cliente MCP)
   │  JSON-RPC por stdio
   ▼
meu-mcp-server/src/index.ts    resolve a raiz, conecta o transporte stdio, logs só em stderr
meu-mcp-server/src/server.ts   registerTool + schema Zod; traduz ScanError em resposta de erro
meu-mcp-server/src/scanner.ts  validação, contenção na raiz, leitura limitada, varredura
   │  import relativo
   ▼
packages/core/src/redaction.ts   detectSecrets (padrões nomeados)
```

### Fluxo de dados **[FATO]**

1. O SDK valida `path` e `maxFindings` contra o schema.
2. `validateInput` valida de novo e normaliza o caminho (rejeita absolutos, `..`, caracteres inválidos, nomes e segmentos proibidos).
3. `realpath(resolve(raiz, rel))` segue symlinks; se o destino real sair da raiz, `E_OUTSIDE_ROOT`. Os mesmos nomes proibidos são reaplicados ao destino real.
4. Abre o arquivo somente leitura (`O_RDONLY`), confere que é arquivo regular, que não tem outros hardlinks (`nlink` = 1, senão `E_DENIED`) e que `stat.size` ≤ 1 MiB.
5. Lê do próprio handle, com teto de 1 MiB + 1 byte (o arquivo pode crescer depois do `stat`); se passar do teto, `E_TOO_LARGE`.
6. Rejeita binário e mais de 20 000 linhas; varre as linhas com `detectSecrets` e monta o resultado.

### Fronteiras de confiança **[DECISÃO]**

| Origem | Confiança | Tratamento |
|---|---|---|
| Argumentos da tool (vêm do modelo) | não confiável | schema + validação repetida + allowlist de raiz |
| Conteúdo e nome do arquivo | não confiável | só passa por regex; nunca é interpretado, executado nem devolvido |
| Variável `CALIXTO_MCP_ROOT` | confiável (configurada pelo dono da máquina) | resolvida uma vez na partida |
| `redaction.ts` | confiável (código do projeto) | importado em tempo de build |
| Saída para o modelo | tratada como dado | só números, rótulos fixos e caminho relativo |

---

## 5.1 Segurança: riscos, mitigações e risco residual

| Risco | Impacto | Mitigação implementada **[FATO]** | Risco residual |
|---|---|---|---|
| Prompt Injection (texto no arquivo ou no `path`) | modelo induzido a vazar segredo ou ampliar acesso | o conteúdo nunca é devolvido nem interpretado; a saída só tem números e rótulos fixos; nada é executado | **[HIPÓTESE]** baixo: o nome do arquivo volta em `file`, e um nome com texto de instrução chegaria ao modelo; os caracteres aceitos limitam, mas não eliminam isso |
| Entrada gigante | esgotar memória ou CPU | `path` ≤ 260; arquivo ≤ 1 MiB (checado em `stat` e na leitura); ≤ 20 000 linhas; ≤ 100 achados; prazo de 5 s | o prazo só é checado a cada 1000 linhas; uma linha única de ~1 MiB ocupa a CPU sem checagem intermediária e **não é interrompida**. **[FATO]** `adversarial.test.ts` mede 6 linhas de 1 MiB desenhadas para estressar os regex (Bearer + espaços, JSON sem fechar, flood de `sk-`...) e exige < 5 s; isso só prova que esses 6 casos terminam rápido, não que outro payload não seja lento |
| Dados malformados | travar ou resposta enganosa | tipo/faixa validados; binário rejeitado; erros com código fixo | UTF-8 inválido é decodificado com substituição, sem erro |
| Acesso não autorizado (traversal, symlink, arquivos de segredo) | ler fora da raiz ou um `.env` | rejeita absolutos e `..`; `realpath` e contenção na raiz; nomes proibidos reaplicados ao destino real; nomes de dispositivo bloqueados; nome iniciado por `.env` bloqueado; `:` e caracteres de controle rejeitados (cobre fluxos alternativos NTFS `arq::$DATA`); **hardlink: arquivo com `nlink > 1` é negado (`E_DENIED`), checado no handle já aberto** (risco levantado na primeira versão deste documento e **MITIGADO** no código) | **[HIPÓTESE]** janela TOCTOU entre `realpath` e `open`: a contenção na raiz não é reverificada depois do `open`, então a troca de um symlink nessa janela não é coberta; nomes curtos 8.3: o teste existente aceita `E_DENIED` **ou** `E_NOT_FOUND`, então não prova que o atalho 8.3 chegou a ser resolvido (depende de o volume ter 8.3 habilitado, não verificado) |
| Vazamento de dados | segredo ou caminho interno exposto | resposta sem trecho do segredo; erros com mensagem fixa e sem caminho absoluto; diagnóstico só em stderr; stdout reservado ao protocolo | `kind` e a linha revelam que existe um segredo e de que tipo. O stderr de partida imprime a raiz absoluta (não vai ao modelo, mas pode aparecer em logs do cliente) |
| Falso negativo | segredo não detectado | nenhuma | cobertura limitada aos 8 padrões; segredo quebrado em duas linhas não é visto. A tool diz "nenhum achado conhecido", nunca "arquivo limpo" |

As colunas "Mitigação" descrevem o **código**. Agora existem `tests/tool.test.ts` e `tests/adversarial.test.ts` (**[FATO]**, li os títulos dos testes). O orquestrador relata `npm test` completo com 195 passed e 3 skipped; **não rodei esses comandos**, então o resultado abaixo é relato (seção 8). Cobertura por risco:

| Risco | Tem teste | Situação |
|---|---|---|
| Prompt Injection (conteúdo e `path`) | sim | testes de conteúdo hostil e de `path` com instrução, inclusive sobre stdio real; passaram, segundo o relato |
| Entrada gigante | sim | arquivo > 1 MiB, > 20 000 linhas, `path` > 260, 6 linhas de 1 MiB; passaram, segundo o relato |
| Dados malformados | sim | binário, UTF-8 inválido, tipos errados, JSON-RPC malformado |
| Traversal, caminho absoluto/UNC, ADS, dispositivos | sim | passaram, segundo o relato |
| Nomes proibidos e `.env*` | sim | passaram, segundo o relato |
| Hardlink | sim | passaram, segundo o relato |
| Symlink/junção de **diretório** | sim | passaram, segundo o relato |
| Symlink de **arquivo** | **3 testes, todos PULADOS** neste Windows (sem privilégio para criar symlink de arquivo) | **sem prova executada.** A contenção por `realpath` só é exercida por 1 teste (ver M2 na seção 8) |
| Nomes 8.3 | teste fraco | aceita `E_DENIED` ou `E_NOT_FOUND`; não prova |
| TOCTOU entre `realpath` e `open` | não | sem teste |
| Vazamento por stdout/stderr, variáveis de ambiente | sim | stdout só com protocolo; teste de variável de ambiente no `path` |

---

## 6. Critérios de aceite

Legenda: **[x]** = executado e relatado pelo orquestrador (não reexecutei; saídas na seção 8); **[ ]** = sem evidência até agora.

- [x] `npm install` e `npm run build` concluem sem erro em `meu-mcp-server/`.
- [x] Servidor responde via stdio, com stdout só de protocolo e logs em stderr (há testes sobre stdio real).
- [x] Claude Code conecta (`claude mcp add --transport stdio ...`): `claude mcp get` mostrou `Connected`. Observação: foi verificado por `claude mcp get`, não vi registro de `/mcp` na sessão interativa.
- [x] A tool devolve achados corretos para um arquivo válido (chamada headless via `claude -p`, seção 8).
- [x] Testes adversariais executados: vazio, gigante, prompt injection e ataque específico (traversal, hardlink, junção, nomes de dispositivo), como testes vitest sobre o handler e o transporte stdio.
- [x] Verificação por mutação: 13 defesas removidas uma a uma, todas detectadas (M7 e M8 só em conjunto; M2 por 1 único teste).
- [x] Testes do core continuam passando após a mudança em `redaction.ts` (11 arquivos ok).
- [ ] **MCP Inspector utilizado.** O relato do orquestrador não cita o Inspector; os testes rodam via vitest e `claude -p`. A atividade pede o Inspector explicitamente: falta executá-lo (modo CLI serve) ou registrar que não foi usado.
- [ ] `LOG-INJECTION-TEMPLATE.md` (arquivo existe, 193 linhas) e `README.md` (existe) conferidos contra o código e a evidência real: não revisados por mim.
- [ ] Commit realizado: nada commitado; `DECISAO-ESCOPO.md`, `LOG-INJECTION-TEMPLATE.md`, `meu-mcp-server/` e `redaction.test.ts` estão sem versionamento e `redaction.ts` está modificado.

---

## 7. Decisões técnicas

| Decisão | Alternativas | Justificativa |
|---|---|---|
| Uma única tool, `scan_file_for_secrets` | várias tools genéricas (`read_file`, `search`) | a atividade pede uma tool útil, não várias genéricas; ler arquivo cru expõe o segredo |
| `tsc` com `rootDir: ".."` e import relativo de `redaction.ts` | copiar a lógica; publicar `@calixto/core` como pacote | reaproveita o código real sem duplicar nem criar etapa de publicação. Custo: a saída vai para `build/index.js` e inclui `build/packages/core/src/redaction.js`, e `package.json` (`main`, `start`, `inspector`) aponta para esse caminho |
| Devolver só `line`, `kind`, `count` | devolver trecho mascarado | mesmo mascarado, o trecho revela prefixo e sufixo do segredo |
| Raiz fixa (`CALIXTO_MCP_ROOT`, padrão cwd) | `path` absoluto livre | a allowlist de recurso é imposta no servidor, não por instrução ao modelo |
| `realpath` + reaplicar nomes proibidos ao destino | só checar o texto do caminho | symlinks poderiam apontar para um `.env` |
| Ler do handle aberto com teto de bytes | `readFile` após `stat` | o arquivo pode crescer entre `stat` e leitura |
| Mensagens de erro fixas por código | repassar a mensagem do sistema | evita eco de entrada e de caminho absoluto |
| Versões exatas de SDK e zod | faixas `^` | reprodutibilidade; SDK 1.32.2 foi publicado em 2026-10-23, acima do mínimo de 7 dias da regra do projeto (ADR 0004) **[FATO]** (data via `npm view`) |
| Código compilado com `tsc` para rodar em `node build/...` | rodar `.ts` direto | o comando de referência da atividade usa `node build/index.js`; a estrutura difere (ver acima) |

### Trade-offs

- Segurança em primeiro lugar: nomes sensíveis são negados mesmo que o usuário queira escaneá-los, e isso é justamente o caso em que um scanner seria mais útil. **[DECISÃO]** Prefere-se negar a arriscar leitura de um arquivo de credencial.
- A regra `/^\.env/i` é por prefixo: também nega arquivos legítimos como `.environment.md`. **[FATO]** (consequência da regex) Aceito para não depender de uma lista de sufixos.
- Negar `nlink > 1` fecha o bypass por hardlink, mas também nega arquivos comuns que por acaso tenham mais de um link. **[DECISÃO]**
- Varredura por linha é simples e limita memória, mas perde segredos que atravessam linhas.
- O prazo de 5 s é cooperativo, não interrompe uma operação síncrona longa.

---

## 8. Evidência

**Origem da evidência.** Tudo abaixo foi executado pelo orquestrador e relatado ao Arquiteto; este documento **não reexecutou** os comandos. O que eu mesmo verifiquei lendo arquivos: a lista dos testes e dos testes pulados (`tool.test.ts`, `adversarial.test.ts`), que `redaction.test.ts` existe com 4 `it`, que `packages/core/package.json` tem `"type": "module"`, e o código de `scanner.ts`. Saídas brutas de terminal não foram coladas aqui: quem precisar delas deve refazer os comandos da seção "Reprodução".

### Resultados relatados

| Item | Comando | Resultado relatado |
|---|---|---|
| Build | `npm run build` (em `meu-mcp-server/`) | ok |
| Testes do servidor e do projeto | `npm test` | **195 passed, 3 skipped**, exit 0. A linha de base de uma cópia isolada deu o mesmo (195 passed, 3 skipped) |
| Suíte do core | (comando não informado no relato) | 11 arquivos ok |
| `detectSecrets` | `packages/core/test/redaction.test.ts` | 4 testes ok; com a função retornando `[]`, 3 dos 4 falham |
| Claude Code | `claude mcp add calixto-secret-scanner --transport stdio -e CALIXTO_MCP_ROOT=... -- node <build>` e `claude mcp get` | `Status: Connected` |
| Chamada válida | `claude -p` chamando `scan_file_for_secrets` em `sample.txt` | `{"file":"sample.txt","bytesScanned":77,"linesScanned":4,"findingsCount":2,"truncated":false,"findings":[{"line":2,"kind":"sk-key","count":1},{"line":3,"kind":"json-credential","count":1}]}`, sem negação de permissão |

Os 3 testes pulados são os de **symlink de arquivo** (`adversarial.test.ts`, linhas 223, 229 e 236, com `ctx.skip()`), porque este Windows não permite criar symlink de arquivo sem privilégio. **[FATO]** (o código mostra o `skip`; que são exatamente esses 3 é consistente com a contagem, mas não vi a saída do vitest).

### Verificação por mutação do `scanner.ts`

Cada linha remove **uma** defesa e roda `npm test`; o resultado é o número de testes que passaram a falhar.

| # | Defesa removida | Testes que falham |
|---|---|---|
| M1 | checagem de `..` | 3 |
| M2 | contenção por `realpath` (`isInside`) | **1** |
| M3 | hardlink (`nlink > 1`) | 5 |
| M4 | regra de nomes negados | 29 |
| M5 | checagem de binário | 2 |
| M6 | nomes de dispositivo do Windows | 12 |
| M7 | só a checagem de tamanho por `stat` | **0** |
| M8 | só a checagem de tamanho pós-leitura | **0** |
| M7+M8 | as duas juntas | 2 |
| M9 | limite de linhas | 2 |
| M10 | rejeição de caminho absoluto | 6 |
| M11 | segmentos `.git` / `node_modules` | 7 |
| M12 | caractere inválido (inclui `:` de fluxos NTFS) | 14 |
| M13 | faixa de `maxFindings` | 4 |

Leitura honesta: M7 e M8 não falham sozinhas por serem redundantes de propósito (cada uma cobre a outra); só a remoção conjunta é detectada. **M2 é o ponto fraco**: a contenção por `realpath` só é exercida por 1 teste, porque os 3 testes de symlink de arquivo estão pulados. Em Linux ou num Windows com privilégio de symlink, esse risco ganharia cobertura real. Isto é um limite de verificação, não prova de defesa.

### Dependência de build descoberta

O build só funciona se `packages/core/package.json` tiver `"type": "module"`; sem isso `redaction.ts` compila como CommonJS e o servidor não sobe. **[FATO]** o arquivo já tem esse campo e não consta como modificado no `git status`. Quem alterar esse campo quebra o servidor.

### O que não foi verificado

- **MCP Inspector:** não há relato de uso (ver seção 6).
- `/mcp` numa sessão interativa do Claude Code: foi usado `claude mcp get`.
- Symlink de arquivo: sem execução (testes pulados).
- Nomes 8.3: o teste é tolerante e não prova resolução do atalho.
- TOCTOU entre `realpath` e `open`: sem teste.
- Linhas únicas de 1 MiB com outros payloads: só 6 casos medidos.
- Comportamento em Linux/macOS: não testado.
- Commit: nenhum (nada versionado ainda).

### Reprodução

```
cd meu-mcp-server
npm install
npm run build
npm test
npx @modelcontextprotocol/inspector node build/index.js
claude mcp add calixto-secret-scanner --transport stdio -e CALIXTO_MCP_ROOT=<pasta> -- node <caminho-absoluto>/build/index.js
```
