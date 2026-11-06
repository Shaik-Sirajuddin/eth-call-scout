import crypto from 'node:crypto';

function normalize(value, path = '$') {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`${path} contains a non-finite number`);
    return value;
  }
  if (Array.isArray(value)) return value.map((entry, index) => normalize(entry, `${path}[${index}]`));
  if (value && typeof value === 'object' && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)) {
    return Object.fromEntries(Object.keys(value).sort().map((key) => {
      if (value[key] === undefined) throw new TypeError(`${path}.${key} is undefined`);
      return [key, normalize(value[key], `${path}.${key}`)];
    }));
  }
  throw new TypeError(`${path} is not canonical JSON data`);
}

export function canonicalJson(value) { return JSON.stringify(normalize(value)); }

export function sha256(value) {
  return crypto.createHash('sha256').update(canonicalJson(value)).digest('hex');
}
