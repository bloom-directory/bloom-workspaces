import { createHash } from "node:crypto";

/**
 * Dev-only mock of the in-guest Bloom ceremony outbox. It lets the relay
 * transport run end to end on the process runtime without KVM. It performs no
 * real WebAuthn verification: `approve` accepts any well-formed assertion.
 * Forbidden in public mode (see assertSafeConfiguration).
 */
export type MockCeremonyRequest = {
  workspaceId: string;
  txId: string;
  chain: string;
  wallet: string;
  planMd: string;
};

export type CeremonyRequestView = {
  id: string;
  chain: string;
  wallet: string;
  planMd: string;
  ceremonyUrl: string | null;
  challenge: string;
  /** Original staged intent JSON, surfaced so the user can re-stage and sign in their own (custody-holding) bloom. Null when not available. */
  intent: string | null;
  /** "ceremony" = approve in-workspace (mock/relay test path); "custody" = watch-only wallet, must sign on your own device. */
  signing: "ceremony" | "custody";
};

export class MockCeremonyStore {
  private readonly requests = new Map<string, MockCeremonyRequest>();

  seed(request: MockCeremonyRequest): void { this.requests.set(request.txId, request); }

  pending(workspaceId: string): { requests: CeremonyRequestView[] } {
    const requests = [...this.requests.values()]
      .filter((request) => request.workspaceId === workspaceId)
      .map((request) => ({
        id: request.txId,
        chain: request.chain,
        wallet: request.wallet,
        planMd: request.planMd,
        ceremonyUrl: null,
        challenge: this.challengeFor(request),
        intent: null,
        signing: "ceremony" as const,
      }));
    return { requests };
  }

  /** Returns true if the request existed for this workspace and was resolved. */
  approve(workspaceId: string, txId: string): boolean {
    const request = this.requests.get(txId);
    if (!request || request.workspaceId !== workspaceId) return false;
    this.requests.delete(txId);
    return true;
  }

  private challengeFor(request: MockCeremonyRequest): string {
    return createHash("sha256").update(`${request.txId}:${request.planMd}`).digest().subarray(0, 32).toString("base64");
  }
}
