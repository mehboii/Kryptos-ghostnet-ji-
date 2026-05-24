export class ReplayAttackError extends Error {
  readonly nodeId: string;
  readonly receivedSeq: number;
  readonly lastSeq: number;

  constructor(nodeId: string, receivedSeq: number, lastSeq: number) {
    super(`Replay detected from ${nodeId}: seq ${receivedSeq} <= last ${lastSeq}`);
    this.name = 'ReplayAttackError';
    this.nodeId = nodeId;
    this.receivedSeq = receivedSeq;
    this.lastSeq = lastSeq;
  }
}

export class StaleMessageError extends Error {
  readonly nodeId: string;
  readonly ageMs: number;

  constructor(nodeId: string, ageMs: number) {
    super(`Stale message from ${nodeId}: ${ageMs}ms old (max ${300_000}ms)`);
    this.name = 'StaleMessageError';
    this.nodeId = nodeId;
    this.ageMs = ageMs;
  }
}

export class FutureMessageError extends Error {
  readonly nodeId: string;
  readonly skewMs: number;

  constructor(nodeId: string, skewMs: number) {
    super(`Future message from ${nodeId}: ${skewMs}ms ahead (max ${60_000}ms)`);
    this.name = 'FutureMessageError';
    this.nodeId = nodeId;
    this.skewMs = skewMs;
  }
}
