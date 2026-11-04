# calixto-secret-scanner (servidor MCP)

Servidor MCP por **stdio** que expõe uma única tool, `scan_file_for_secrets`: ela diz **em quais linhas** de um arquivo de texto do workspace aparecem chaves de API, bearer tokens ou campos de credencial. Devolve número da linha e tipo do segredo, **nunca o segredo**. Reaproveita as regras de `packages/core/src/redaction.ts` do Calixto AI (`detectSecrets`).

Requisitos: Node >= 24.14, npm.

## Instalação e build

```bash
cd meu-mcp-server
npm install
npm run build
```

O servidor importa `../packages/core/src/redaction.ts`, então o `tsc` compila com `rootDir` na raiz do repositório. Por isso o entry point compilado é:

```
meu-mcp-server/build/index.js
```

(e não `build/index.js`).

## Configuração

| Variável | Efeito | Padrão |
|---|---|---|
| `CALIXTO_MCP_ROOT` | Diretório raiz permitido. Só arquivos dentro dele (após resolver symlinks) podem ser lidos. | diretório de trabalho do processo |

Ao iniciar, o servidor escreve `ready (stdio), root=...` em **stderr**. O stdout fica reservado ao protocolo MCP.

## Conectar ao Claude Code

```bash
claude mcp add --transport stdio calixto-secret-scanner -e CALIXTO_MCP_ROOT=/caminho/do/projeto -- node /caminho/completo/meu-mcp-server/build/index.js
```

Depois, no Claude Code, rode `/mcp` e confira que `calixto-secret-scanner` aparece conectado.

> **Não verificado:** o comando `claude mcp add` e o `/mcp` não foram executados nesta documentação (isso altera a configuração do Claude Code do usuário). A conexão por stdio foi verificada com um cliente MCP do SDK e com o Inspector, descritos abaixo.

## A tool `scan_file_for_secrets`

Entrada:

| Campo | Tipo | Obrigatório | Limite |
|---|---|---|---|
| `path` | string | sim | 1 a 260 caracteres, relativo à raiz permitida |
| `maxFindings` | inteiro | não | 1 a 100 (padrão 50) |

Saída (`structuredContent`, também serializada em `content[0].text`):

```json
{
  "file": "sample.txt",
  "bytesScanned": 77,
  "linesScanned": 4,
  "findingsCount": 2,
  "truncated": false,
  "findings": [
    { "line": 2, "kind": "sk-key", "count": 1 },
    { "line": 3, "kind": "json-credential", "count": 1 }
  ]
}
```

Tipos (`kind`): `sk-key`, `bearer-token`, `github-token`, `google-api-key`, `anthropic-key`, `xai-key`, `deepseek-key`, `json-credential`.

Erros controlados (`isError: true`, texto fixo, sem caminho absoluto nem eco da entrada):

| Código | Quando |
|---|---|
| `E_VALIDATION` | tipo errado, vazio, maior que 260, caracteres de controle ou `< > : " \| ? *`, `maxFindings` fora de 1..100, segmento terminado em ponto/espaço, alvo que não é arquivo |
| `E_OUTSIDE_ROOT` | caminho absoluto, segmento `..`, ou symlink que escapa da raiz |
| `E_DENIED` | nome que começa com `.env` (`.env`, `.env.local`, `.envrc`, `.env-prod`, sem diferenciar maiúsculas), `*.pem`, `*.key`, `*.pfx`, `*.p12`, `*.kdbx`, `id_rsa*`/`id_dsa*`/`id_ecdsa*`/`id_ed25519*`, `credentials*`, segmentos `.git` ou `node_modules`, nomes de dispositivo do Windows (`CON`, `NUL`, `COM1`...), e arquivo com mais de um hardlink (`nlink > 1`) |
| `E_NOT_FOUND` | arquivo inexistente |
| `E_TOO_LARGE` | arquivo > 1 MiB ou > 20.000 linhas |
| `E_BINARY` | byte nulo nos primeiros 8 KiB |
| `E_TIMEOUT` | varredura passou de 5 s |
| `E_INTERNAL` | falha inesperada (detalhe só em stderr, sem dados) |

## Limites

Arquivo até 1 MiB (leitura limitada a esse teto mesmo se o arquivo crescer depois do `stat`), 20.000 linhas, 100 achados por chamada (`truncated: true` se houver mais), prazo de 5 s, uma tool, somente leitura.

## Segurança

Fatos do código (`src/scanner.ts`, `src/server.ts`):

- O conteúdo do arquivo é tratado como dado: só passa por expressões regulares de detecção; nunca é executado, interpretado ou devolvido.
- A resposta contém apenas linha, tipo e contagem; o texto do segredo não sai do processo.
- Contenção na raiz: `realpath` da raiz e do alvo, depois checagem de que o alvo real está dentro da raiz. A lista de nomes negados é aplicada de novo ao destino real de um symlink.
- Hardlinks: um arquivo com mais de um nome (`nlink > 1`) é negado, porque um hardlink daria a um arquivo negado (ex.: `.env`) um segundo nome inofensivo que a checagem por nome não enxerga. Efeito colateral: arquivos legítimos com hardlink também são recusados.
- A leitura usa o mesmo handle aberto, com teto de bytes, para reduzir a janela entre checagem e uso.
- Nenhum comando externo é executado; não há acesso à rede.
- Erros têm mensagem fixa por código. Logs de diagnóstico vão só para stderr.

Limites conhecidos: a detecção é por padrões conhecidos (um segredo de formato desconhecido não é encontrado); a janela entre checar e abrir o arquivo foi reduzida, não eliminada.

## Testar

MCP Inspector, modo CLI (**verificado**: lista a tool `scan_file_for_secrets` com o schema de entrada):

```bash
npx @modelcontextprotocol/inspector --cli node build/index.js --method tools/list
```

Chamada da tool pelo Inspector CLI (**verificado**), a partir de `meu-mcp-server/`, com a raiz apontando para a pasta alvo:

```bash
npx @modelcontextprotocol/inspector --cli -e CALIXTO_MCP_ROOT=/pasta/alvo node build/index.js --method tools/call --tool-name scan_file_for_secrets --tool-arg path=sample.txt
```

> **Atenção (verificada):** o Inspector CLI **não repassa** variáveis de ambiente do shell ao servidor. Com `CALIXTO_MCP_ROOT` definida só no shell, o servidor iniciou com a raiz igual ao diretório atual (`root=` no stderr) e respondeu `E_NOT_FOUND` para um arquivo que existia na pasta alvo. Use a opção `-e CALIXTO_MCP_ROOT=...` do Inspector, como acima. Confira sempre a linha `ready (stdio), root=...` no stderr.

Interface gráfica: `npm run inspector`.

Um cliente MCP do SDK (`StdioClientTransport`) também foi usado para um teste de ponta a ponta: listou a tool, escaneou um arquivo com dois segredos falsos (2 achados, linhas 2 e 3, sem o texto do segredo) e recebeu `E_OUTSIDE_ROOT` para `../x`.

Testes automatizados:

```bash
npm test
```

Resultado observado em 2026-11-04 (Windows 11, Node 24): 2 arquivos (`tests/tool.test.ts`, `tests/adversarial.test.ts`), **185 passaram, 3 ignorados**, 0 falhas.

> **Limite verificado:** os 3 testes ignorados são os de **symlink de arquivo** (fora da raiz, apontando para `.env`, e symlink quebrado). Eles se auto-ignoram quando o sistema não permite criar symlink de arquivo, como nesta conta do Windows. Ou seja, a defesa contra symlink de arquivo **não foi exercitada por testes nesta máquina**. Para executá-los, rode em um terminal com permissão de criar symlinks (Modo de Desenvolvedor do Windows ou administrador) ou em Linux/macOS.

Os testes de `detectSecrets` ficam em `packages/core/test/redaction.test.ts` e rodam no pacote core, não aqui.
