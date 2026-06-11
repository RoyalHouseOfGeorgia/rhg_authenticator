/** JSON-serializable value types. */
export type JsonValue = string | number | boolean | null | JsonObject | JsonValue[];
export type JsonObject = { [key: string]: JsonValue };

/** Maximum allowed nesting depth for canonicalized objects. */
export const MAX_DEPTH = 4;

/**
 * Compare strings by Unicode code point. Go's sort.Strings orders by UTF-8
 * byte, which is equivalent to code-point order — but the default
 * Array.prototype.sort comparison uses UTF-16 code units, which orders
 * characters above U+FFFF (surrogate pairs) differently. Keys must sort
 * identically in both languages or canonical bytes (and signatures) diverge.
 */
function compareCodePoints(a: string, b: string): number {
  let i = 0;
  while (i < a.length && i < b.length) {
    const ca = a.codePointAt(i) as number;
    const cb = b.codePointAt(i) as number;
    if (ca !== cb) {
      return ca - cb;
    }
    i += ca > 0xffff ? 2 : 1;
  }
  return a.length - b.length;
}

/**
 * Recursively sort object keys and normalize values for deterministic
 * JSON serialization.
 */
function sortAndNormalize(value: JsonValue, depth: number): JsonValue {
  if (value === null) {
    return null;
  }

  switch (typeof value) {
    case 'boolean':
      return value;

    case 'number':
      if (!Number.isFinite(value)) {
        throw new TypeError(`Non-finite number is not valid JSON: ${value}`);
      }
      if (Object.is(value, -0)) {
        throw new TypeError('Negative zero is not a valid JSON value');
      }
      return value;

    case 'string':
      return value.normalize('NFC');

    case 'object': {
      if (depth >= MAX_DEPTH) {
        throw new Error('object exceeds maximum nesting depth');
      }
      if (Array.isArray(value)) {
        return value.map((el) => sortAndNormalize(el, depth + 1));
      }
      // Plain object — sort keys and recurse. Keys are sorted but intentionally
      // NOT NFC-normalized: a verifier matches JSON object keys byte-for-byte, so
      // normalizing them would break the cross-language (Go/TS) canonical-byte
      // parity that signatures depend on. String *values* ARE NFC-normalized (see
      // the 'string' case above). Keep this in agreement with go/core/canonical.go.
      const sorted = Object.create(null) as JsonObject;
      for (const key of Object.keys(value).sort(compareCodePoints)) {
        if (key === '__proto__') {
          throw new TypeError('"__proto__" is not allowed as a JSON key');
        }
        const v = value[key];
        if (v === undefined) {
          throw new TypeError(
            `undefined value at key "${key}" is not valid JSON`,
          );
        }
        sorted[key] = sortAndNormalize(v, depth + 1);
      }
      return sorted;
    }

    default:
      throw new TypeError(`Unsupported value type: ${typeof value}`);
  }
}

const encoder = new TextEncoder();

/**
 * Produce a deterministic canonical UTF-8 byte representation of a JSON
 * object.  Object keys are sorted recursively, strings are NFC-normalized,
 * and the output contains no extraneous whitespace.
 */
export function canonicalize(obj: JsonObject): Uint8Array {
  const normalized = sortAndNormalize(obj, 0) as JsonObject;
  const json = JSON.stringify(normalized);
  return encoder.encode(json);
}
