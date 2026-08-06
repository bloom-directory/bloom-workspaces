import { z } from "zod";

const EvmAddress = z.string().regex(/^0x[0-9a-f]{40}$/);

export const BloomGuestStatus = z.object({
  available: z.boolean(),
  mount: z.object({ path: z.literal("/bloom"), mounted: z.boolean() }),
  identity: z.object({ kind: z.literal("watch"), address: EvmAddress }).nullable(),
  capabilities: z.object({
    files: z.boolean(),
    jobs: z.boolean(),
    bloomRead: z.boolean(),
    walletSigning: z.literal(false),
    transactions: z.literal(false),
  }),
  helper: z.object({ name: z.literal("bloom-workspace"), protocolVersion: z.literal(1) }),
}).superRefine((status, context) => {
  if (status.available && status.identity === null) context.addIssue({ code: "custom", path: ["identity"], message: "available Bloom requires a watch identity" });
});

export type BloomGuestStatus = z.infer<typeof BloomGuestStatus>;
