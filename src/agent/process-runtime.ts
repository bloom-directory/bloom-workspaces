import type { RuntimeSpec } from "./runtime.js";
import { PtyRuntime } from "./pty-runtime.js";

/** Development-only. This is intentionally rejected by public-mode configuration. */
export class ProcessRuntime extends PtyRuntime {
  protected async command(_spec: RuntimeSpec, workspaceDir: string) {
    return {
      file: "/bin/bash",
      args: ["--noprofile", "--norc"],
      cwd: workspaceDir,
      env: {
        HOME: workspaceDir,
        LANG: "C.UTF-8",
        PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        PS1: "\\[\\e[38;5;114m\\]bloom-dev\\[\\e[0m\\]:\\w$ ",
        TERM: "xterm-256color",
      },
      cleanup: this.cleanupDirectory(_spec.id),
    };
  }
}
