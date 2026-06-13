/**
 * TrafficModel — a live statistical model of GhostNet's real outbound traffic,
 * shared by TrafficShaper (cover traffic) and DecoyEngine (decoy traffic).
 *
 * WHY: an attacker is assumed to have DECOMPILED the app — the decoy/cover
 * algorithm is PUBLIC. Indistinguishability therefore cannot rely on the
 * algorithm being secret; it must be statistical. So instead of emitting cover/
 * decoy traffic on a fixed cadence (which is itself a fingerprint), we observe
 * the distribution of real inter-arrival times and frame sizes and draw cover/
 * decoy events from the SAME distribution.
 *
 * Method:
 *  - Inter-arrival: a bootstrap reservoir of recent observed gaps. We sample by
 *    drawing an observed gap at random (so the synthetic distribution converges
 *    to the real one). Before enough data exists, we fall back to an exponential
 *    (Poisson process) with a supplied mean — memoryless, the maximum-entropy
 *    model for "events at an average rate", and crucially NOT a regular metronome.
 *  - Size: a histogram over the fixed padding buckets; we sample a bucket with
 *    probability proportional to how often real frames landed in it (fallback:
 *    uniform over buckets).
 *
 * No identifiers are stored — only gap durations (ms) and size-bucket counts.
 */

import type { RandomSource } from './types';

const DEFAULT_RESERVOIR = 256;

export interface TrafficModelOptions {
  readonly buckets: readonly number[];
  /** Max recent gaps kept for bootstrap sampling. */
  readonly reservoirSize?: number;
  /** Min observed gaps before we bootstrap instead of using the prior. */
  readonly minSamplesForBootstrap?: number;
}

export class TrafficModel {
  private readonly buckets: readonly number[];
  private readonly reservoirSize: number;
  private readonly minSamples: number;

  private readonly gaps: number[] = [];
  private gapWrite = 0;
  private readonly bucketCounts: number[];
  private lastObservedAt: number | null = null;

  constructor(
    private readonly random: RandomSource,
    options: TrafficModelOptions,
  ) {
    this.buckets = options.buckets;
    this.reservoirSize = options.reservoirSize ?? DEFAULT_RESERVOIR;
    this.minSamples = options.minSamplesForBootstrap ?? 8;
    this.bucketCounts = new Array<number>(this.buckets.length).fill(0);
  }

  /** Record one real outbound frame: its (padded) size and the time it was sent. */
  observe(sizeBytes: number, atMs: number): void {
    if (this.lastObservedAt !== null) {
      const gap = atMs - this.lastObservedAt;
      if (gap >= 0) this.recordGap(gap);
    }
    this.lastObservedAt = atMs;
    this.recordSize(sizeBytes);
  }

  /** Number of observed gaps currently retained (for tests/telemetry). */
  get sampleCount(): number {
    return this.gaps.length;
  }

  /**
   * Draw an inter-arrival delay (ms). Uses the observed distribution once enough
   * samples exist; otherwise an exponential with `fallbackMeanMs` (Poisson).
   */
  sampleGapMs(fallbackMeanMs: number): number {
    if (this.gaps.length >= this.minSamples) {
      const idx = this.random.int(0, this.gaps.length - 1);
      // Small multiplicative jitter so we don't replay the exact observed value.
      const jitter = 0.85 + (this.random.int(0, 30) / 100); // 0.85–1.15
      return Math.max(1, Math.round(this.gaps[idx] * jitter));
    }
    return this.exponential(fallbackMeanMs);
  }

  /** Draw a frame size (a padding bucket) from the observed size histogram. */
  sampleSizeBytes(): number {
    const total = this.bucketCounts.reduce((a, b) => a + b, 0);
    if (total === 0) {
      // Uniform prior over buckets.
      return this.buckets[this.random.int(0, this.buckets.length - 1)];
    }
    let r = this.random.int(0, total - 1);
    for (let i = 0; i < this.buckets.length; i++) {
      if (r < this.bucketCounts[i]) return this.buckets[i];
      r -= this.bucketCounts[i];
    }
    return this.buckets[this.buckets.length - 1];
  }

  /** Exponential (Poisson-process) inter-arrival with the given mean. */
  private exponential(meanMs: number): number {
    const mean = Math.max(1, meanMs);
    // u in (0,1]; -mean*ln(u) ~ Exponential(mean).
    const u = (this.random.int(1, 1_000_000)) / 1_000_000;
    return Math.max(1, Math.round(-mean * Math.log(u)));
  }

  private recordGap(gap: number): void {
    if (this.gaps.length < this.reservoirSize) {
      this.gaps.push(gap);
    } else {
      this.gaps[this.gapWrite] = gap;
      this.gapWrite = (this.gapWrite + 1) % this.reservoirSize;
    }
  }

  private recordSize(sizeBytes: number): void {
    // Attribute to the smallest bucket that fits (the on-wire size class).
    for (let i = 0; i < this.buckets.length; i++) {
      if (sizeBytes <= this.buckets[i]) {
        this.bucketCounts[i]++;
        return;
      }
    }
    this.bucketCounts[this.buckets.length - 1]++;
  }
}
