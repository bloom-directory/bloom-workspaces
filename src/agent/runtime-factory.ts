import type { Config } from "../config.js";
import { FirecrackerRuntime } from "./firecracker-runtime.js";
import { ProcessRuntime } from "./process-runtime.js";
import { QemuRuntime } from "./qemu-runtime.js";

export function createRuntime(config: Config) {
  if (config.runtime === "qemu") return new QemuRuntime(config);
  if (config.runtime === "firecracker") return new FirecrackerRuntime(config);
  return new ProcessRuntime(config.dataDir, config.preinstalledPetals);
}
