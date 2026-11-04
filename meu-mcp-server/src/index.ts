import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { resolveRoot } from "./scanner.ts";
import { createServer } from "./server.ts";

// stdout belongs to the MCP protocol; every diagnostic goes to stderr.
async function main(): Promise<void> {
  const root = await resolveRoot(process.env["CALIXTO_MCP_ROOT"]);
  await createServer(root).connect(new StdioServerTransport());
  console.error(`[calixto-secret-scanner] ready (stdio), root=${root}`);
}

main().catch(() => {
  console.error("[calixto-secret-scanner] failed to start");
  process.exit(1);
});
