import { describe, expect, it } from 'vitest';
import { canonicalize, MAX_DEPTH } from '../canonical.js';
import type { JsonObject } from '../canonical.js';

const decoder = new TextDecoder();

/** Helper: canonicalize and return the JSON string. */
function toJson(obj: JsonObject): string {
  return decoder.decode(canonicalize(obj));
}

describe('canonicalize', () => {
  it('sorts object keys alphabetically', () => {
    expect(toJson({ z: 1, a: 2 })).toBe('{"a":2,"z":1}');
  });

  it('sorts nested object keys recursively', () => {
    const input: JsonObject = { z: { b: 1, a: 2 }, a: { d: 3, c: 4 } };
    expect(toJson(input)).toBe('{"a":{"c":4,"d":3},"z":{"a":2,"b":1}}');
  });

  it('applies NFC normalization to strings (combining chars)', () => {
    // U+0065 (e) + U+0301 (combining acute) → U+00E9 (precomposed é)
    const input: JsonObject = { name: '\u0065\u0301' };
    const result = toJson(input);
    expect(result).toBe('{"name":"\u00e9"}');
  });

  it('produces output with no whitespace', () => {
    const result = toJson({ a: 1, b: 'hello', c: true });
    expect(result).not.toMatch(/\s/);
  });

  it('handles Georgian script characters correctly', () => {
    const input: JsonObject = { letter: '\u10D0' }; // ა
    const result = toJson(input);
    expect(result).toBe('{"letter":"\u10D0"}');
  });

  it('produces deterministic output on repeated calls', () => {
    const input: JsonObject = { z: 1, a: 2, m: { x: 'hello', b: true } };
    const first = canonicalize(input);
    const second = canonicalize(input);
    expect(first).toEqual(second);
  });

  it('matches golden-test v1 credential fixture', () => {
    const credential: JsonObject = {
      date: '2026-03-11',
      detail: 'Awarded for exceptional service',
      honor: 'Knight Commander of the Royal Order of Georgia',
      recipient: 'John Quincy Doe',
      version: 1,
    };

    const expectedJson =
      '{"date":"2026-03-11","detail":"Awarded for exceptional service","honor":"Knight Commander of the Royal Order of Georgia","recipient":"John Quincy Doe","version":1}';
    const expectedBytes = new TextEncoder().encode(expectedJson);

    const result = canonicalize(credential);
    expect(result).toEqual(expectedBytes);
  });

  it('preserves array element order (does not sort arrays)', () => {
    expect(toJson({ a: [3, 1, 2] })).toBe('{"a":[3,1,2]}');
  });

  it('passes null values through', () => {
    expect(toJson({ a: null })).toBe('{"a":null}');
  });

  describe('rejects non-finite and special numbers', () => {
    it('throws on NaN', () => {
      expect(() => canonicalize({ v: NaN as unknown as number })).toThrow(
        /non-finite/i,
      );
    });

    it('throws on Infinity', () => {
      expect(() => canonicalize({ v: Infinity as unknown as number })).toThrow(
        /non-finite/i,
      );
    });

    it('throws on -Infinity', () => {
      expect(() =>
        canonicalize({ v: -Infinity as unknown as number }),
      ).toThrow(/non-finite/i);
    });

    it('throws on negative zero', () => {
      expect(() => canonicalize({ v: -0 as unknown as number })).toThrow(
        /negative zero/i,
      );
    });
  });

  it('rejects undefined values with a clear error', () => {
    const obj = { a: undefined } as unknown as JsonObject;
    expect(() => canonicalize(obj)).toThrow(/undefined/i);
  });

  it('handles supplementary-plane Unicode (emoji) deterministically', () => {
    // U+1F600 Grinning Face — supplementary plane
    const input: JsonObject = { emoji: '\u{1F600}' };
    const first = canonicalize(input);
    const second = canonicalize(input);
    expect(first).toEqual(second);
    // Verify the emoji survives round-trip
    expect(toJson(input)).toBe('{"emoji":"\u{1F600}"}');
  });

  it('handles deeply nested arrays inside objects', () => {
    const input: JsonObject = { b: [{ z: 1, a: 2 }], a: 'first' };
    expect(toJson(input)).toBe('{"a":"first","b":[{"a":2,"z":1}]}');
  });

  it('handles empty objects and arrays', () => {
    expect(toJson({})).toBe('{}');
    expect(toJson({ a: [] })).toBe('{"a":[]}');
    expect(toJson({ a: {} })).toBe('{"a":{}}');
  });

  describe('depth cap', () => {
    it('exports MAX_DEPTH as 4', () => {
      expect(MAX_DEPTH).toBe(4);
    });

    it('passes shallow object { a: 1 } (max depth 0)', () => {
      expect(() => canonicalize({ a: 1 })).not.toThrow();
    });

    it('passes one level of nesting { a: { b: 1 } } (max depth 1)', () => {
      expect(() => canonicalize({ a: { b: 1 } })).not.toThrow();
    });

    it('passes object nested inside array { a: [{ b: 1 }] } (max depth 2)', () => {
      expect(() => canonicalize({ a: [{ b: 1 }] })).not.toThrow();
    });

    it('passes three levels of nesting { a: { b: { c: { d: 1 } } } } (max depth 3)', () => {
      expect(() => canonicalize({ a: { b: { c: { d: 1 } } } })).not.toThrow();
    });

    it('throws at four levels of nesting { a: { b: { c: { d: { e: 1 } } } } } (depth 4 >= MAX_DEPTH)', () => {
      expect(() =>
        canonicalize({ a: { b: { c: { d: { e: 1 } } } } }),
      ).toThrow('object exceeds maximum nesting depth');
    });

    it('throws for mixed object/array nesting that reaches depth 4', () => {
      // root=0, array=1, inner obj=2, inner array=3, c obj=4 → throws
      expect(() =>
        canonicalize({ a: [{ b: [{ c: 1 }] }] }),
      ).toThrow('object exceeds maximum nesting depth');
    });

    it('passes nested arrays up to depth 3 { a: [[[]]] }', () => {
      // root=0, array=1, array=2, array=3 → max depth 3, passes
      expect(() => canonicalize({ a: [[[]]] })).not.toThrow();
    });

    it('throws for nested arrays reaching depth 4 { a: [[[[]]]] }', () => {
      // root=0, array depths 1,2,3,4 → depth 4 >= MAX_DEPTH → throws
      expect(() => canonicalize({ a: [[[[]]]] })).toThrow(
        'object exceeds maximum nesting depth',
      );
    });

    it('passes flat V1 credential (regression test)', () => {
      const credential: JsonObject = {
        date: '2026-03-11',
        detail: 'Awarded for exceptional service',
        honor: 'Knight Commander of the Royal Order of Georgia',
        recipient: 'John Quincy Doe',
        version: 1,
      };
      // root=0, all values are scalars → max depth 0
      expect(() => canonicalize(credential)).not.toThrow();
    });

    it('includes descriptive message in depth error', () => {
      expect(() =>
        canonicalize({ a: { b: { c: { d: { e: 1 } } } } }),
      ).toThrow(/object exceeds maximum nesting depth/);
    });
  });

  describe('prototype pollution protection', () => {
    it('rejects __proto__ key at top level', () => {
      expect(() =>
        canonicalize(JSON.parse('{"__proto__": "evil"}')),
      ).toThrow('"__proto__" is not allowed as a JSON key');
    });

    it('rejects nested __proto__ key', () => {
      expect(() =>
        canonicalize(JSON.parse('{"a": {"__proto__": "evil"}}')),
      ).toThrow('"__proto__" is not allowed as a JSON key');
    });

    it('allows "constructor" as a key', () => {
      const result = toJson({ constructor: 'ok' } as any);
      expect(result).toContain('"constructor"');
    });

    it('allows "hasOwnProperty" as a key', () => {
      const result = toJson({ hasOwnProperty: 'ok' } as any);
      expect(result).toContain('"hasOwnProperty"');
    });
  });
});
