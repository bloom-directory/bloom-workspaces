import { loadConfig } from "../config.js";
import { openDatabase } from "../db.js";
import { startControlPlane } from "./server.js";

const config = loadConfig(process.env, "control");
const control = await startControlPlane(config, openDatabase(config.databasePath));
console.log(`Bloom Workspaces listening on ${config.origin}`);

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => void control.close().finally(() => process.exit(0)));
}
