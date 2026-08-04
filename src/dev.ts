import { loadConfig } from "./config.js";
import { openDatabase } from "./db.js";
import { createRuntime } from "./agent/runtime-factory.js";
import { startAgent } from "./agent/server.js";
import { startControlPlane } from "./control/server.js";

const config = loadConfig();
if (config.publicMode) throw new Error("The combined development process is forbidden in public mode");
const agent = await startAgent(config, createRuntime(config));
const control = await startControlPlane(config, openDatabase(config.databasePath));
console.log(`Bloom Workspaces development server: ${config.origin} (${config.runtime} runtime)`);

async function close() {
  await control.close();
  await agent.close();
}
for (const signal of ["SIGINT", "SIGTERM"] as const) process.once(signal, () => void close().finally(() => process.exit(0)));
