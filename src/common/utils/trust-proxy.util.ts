export type TrustProxySetting = number | string[] | false;

const HOP_COUNT_PATTERN = /^\d+$/;
const TRUSTED_ENTRY_PATTERN = /^(loopback|linklocal|uniquelocal|[0-9A-Fa-f:.]+(\/\d{1,3})?)$/;

export function resolveTrustProxy(raw: string | undefined): TrustProxySetting {
  const value = raw?.trim();
  if (!value) return false;

  if (HOP_COUNT_PATTERN.test(value)) return Number(value);

  const entries = value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

  const invalid = entries.filter((entry) => !TRUSTED_ENTRY_PATTERN.test(entry));
  if (invalid.length > 0) {
    throw new Error(
      `INVALID_TRUST_PROXY: ${invalid.join(', ')} — expected a hop count or a comma-separated list of IPs/CIDRs/loopback/linklocal/uniquelocal`,
    );
  }

  return entries;
}
