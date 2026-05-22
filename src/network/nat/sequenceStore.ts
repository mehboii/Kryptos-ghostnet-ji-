import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { SEQUENCE_STORE_PATH, SEQUENCE_SAVE_INTERVAL_MS } from './constants.js';

const MAX_PEERS = 10_000;
const MAX_SAFE_SEQUENCE = 2 ** 48;

export interface PeerSequenceRecord {
  lastSequence: number;
  lastSeen: number;
}

const activeStores = new Set<SequenceStore>();
let shutdownBound = false;

function bindGlobalShutdown(): void {
  if (shutdownBound) return;
  shutdownBound = true;
  const flush = () => { for (const s of activeStores) s.destroy(); };
  process.once('SIGTERM', flush);
  process.once('SIGINT', flush);
  process.once('beforeExit', flush);
}

export class SequenceStore {
  private store = new Map<string, PeerSequenceRecord>();
  private readonly path: string;
  private saveTimer: ReturnType<typeof setInterval> | null = null;
  private dirty = false;

  constructor(storePath?: string) {
    this.path = resolve(storePath ?? SEQUENCE_STORE_PATH);
    this.load();
    this.saveTimer = setInterval(() => this.saveIfDirty(), SEQUENCE_SAVE_INTERVAL_MS);
    activeStores.add(this);
    bindGlobalShutdown();
  }

  get(nodeId: string): PeerSequenceRecord | undefined {
    return this.store.get(nodeId);
  }

  update(nodeId: string, sequence: number): void {
    if (this.store.size >= MAX_PEERS && !this.store.has(nodeId)) {
      this.evictOldest();
    }
    this.store.set(nodeId, { lastSequence: sequence, lastSeen: Date.now() });
    this.dirty = true;
  }

  has(nodeId: string): boolean {
    return this.store.has(nodeId);
  }

  get size(): number {
    return this.store.size;
  }

  toJSON(): Record<string, PeerSequenceRecord> {
    const obj: Record<string, PeerSequenceRecord> = {};
    for (const [k, v] of this.store) obj[k] = v;
    return obj;
  }

  destroy(): void {
    this.saveIfDirty();
    if (this.saveTimer) {
      clearInterval(this.saveTimer);
      this.saveTimer = null;
    }
    activeStores.delete(this);
  }

  private load(): void {
    try {
      if (!existsSync(this.path)) return;
      const raw = readFileSync(this.path, 'utf8');
      const parsed = JSON.parse(raw);
      if (typeof parsed !== 'object' || parsed === null) return;
      for (const [nodeId, record] of Object.entries(parsed)) {
        const r = record as any;
        if (
          typeof r.lastSequence === 'number' && typeof r.lastSeen === 'number'
          && r.lastSequence >= 0 && r.lastSequence < MAX_SAFE_SEQUENCE
          && Number.isFinite(r.lastSequence) && Number.isFinite(r.lastSeen)
        ) {
          this.store.set(nodeId, { lastSequence: r.lastSequence, lastSeen: r.lastSeen });
        }
      }
    } catch {
      // Missing or corrupt file — start fresh
    }
  }

  private save(): void {
    try {
      const dir = dirname(this.path);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      writeFileSync(this.path, JSON.stringify(this.toJSON(), null, 2), 'utf8');
      this.dirty = false;
    } catch {
      // Disk write failure — non-fatal, in-memory state is authoritative
    }
  }

  private evictOldest(): void {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;
    for (const [k, v] of this.store) {
      if (v.lastSeen < oldestTime) { oldestTime = v.lastSeen; oldestKey = k; }
    }
    if (oldestKey) this.store.delete(oldestKey);
  }

  private saveIfDirty(): void {
    if (this.dirty) this.save();
  }

}
