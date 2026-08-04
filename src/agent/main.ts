import { loadConfig } from "../config.js";
import { createRuntime } from "./runtime-factory.js";
import { startAgent } from "./server.js";

const config = loadConfig(process.env, "agent");
const agent = await startAgent(config, createRuntime(config));
console.log(`Bloom node agent listening on ${config.agentSocket} (${config.runtime})`);

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => void agent.close().finally(() => process.exit(0)));
}
