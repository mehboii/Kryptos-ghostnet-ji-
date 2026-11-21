import { describe, expect, it } from 'vitest';
import { PADDING_BUCKETS } from '../config';
import { padFrame, selectBucket, unpadFrame } from '../modules/TrafficShaper';
import { SeededRandom } from '../testing';
import type { MeshFrame } from '../types';

const rnd = new SeededRandom(42);

describe('padding bucket selection', () => {
  it('rounds up to the next bucket', () => {
    expect(selectBucket(0, PADDING_BUCKETS)).toBe(256);
    expect(selectBucket(1, PADDING_BUCKETS)).toBe(256);
    expect(selectBucket(256, PADDING_BUCKETS)).toBe(256);
    expect(selectBucket(257, PADDING_BUCKETS)).toBe(512);
    expect(selectBucket(512, PADDING_BUCKETS)).toBe(512);
    expect(selectBucket(900, PADDING_BUCKETS)).toBe(1024);
    expect(selectBucket(1025, PADDING_BUCKETS)).toBe(4096);
    expect(selectBucket(4096, PADDING_BUCKETS)).toBe(4096);
  });

  it('rounds oversized frames up to a multiple of the largest bucket', () => {
    expect(selectBucket(4097, PADDING_BUCKETS)).toBe(8192);
    expect(selectBucket(8192, PADDING_BUCKETS)).toBe(8192);
    expect(selectBucket(9000, PADDING_BUCKETS)).toBe(12288);
  });

  it('rejects negative lengths', () => {
    expect(() => selectBucket(-1, PADDING_BUCKETS)).toThrow();
  });
});

describe('padFrame / unpadFrame', () => {
  it('produces a frame whose length is exactly a bucket', () => {
    for (const size of [0, 1, 100, 252, 600, 1024, 5000]) {
      const frame: MeshFrame = { bytes: rnd.bytes(size), to: 'peer-x' };
      const padded = padFrame(frame, PADDING_BUCKETS, rnd);
      const expectedBucket = selectBucket(4 + size, PADDING_BUCKETS);
      expect(padded.bytes.length).toBe(expectedBucket);
    }
  });

  it('is exactly reversible (does not corrupt the ciphertext)', () => {
    for (const size of [0, 1, 31, 200, 255, 1023, 4096, 7000]) {
      const original = rnd.bytes(size);
      const frame: MeshFrame = { bytes: original, to: 'peer-y' };
      const round = unpadFrame(padFrame(frame, PADDING_BUCKETS, rnd));
      expect(round.bytes).toEqual(original);
      expect(round.to).toBe('peer-y');
    }
  });

  it('hides true length: 100 and 200 byte frames land in the same bucket', () => {
    const a = padFrame({ bytes: rnd.bytes(100), to: null }, PADDING_BUCKETS, rnd);
    const b = padFrame({ bytes: rnd.bytes(200), to: null }, PADDING_BUCKETS, rnd);
    expect(a.bytes.length).toBe(b.bytes.length);
  });

  it('rejects a corrupt padded frame whose header overflows the buffer', () => {
    const bad: MeshFrame = { bytes: new Uint8Array([0xff, 0xff, 0xff, 0xff, 1, 2, 3]), to: null };
    expect(() => unpadFrame(bad)).toThrow();
  });
});
