import { lookup as dnsLookup } from "node:dns/promises";
import type { LookupAddress, LookupOptions } from "node:dns";
import type { LookupFunction } from "node:net";
import { isBlockedIp, isAlwaysBlockedIp } from "./ipGuard.js";

export class ResolutionError extends Error {}

export interface PinnedTarget {
  readonly hostname: string;
  readonly pinnedIp: string;
  readonly family: 4 | 6;
  /**
   * A dns.lookup-compatible function that always resolves to the single,
   * already-validated pinned IP — passed as the `lookup` option to http(s).request
   * so the socket connects to exactly the address we validated. This is what
   * defeats DNS rebinding: there is no second resolution to race.
   */
  readonly lookup: LookupFunction;
}

/**
 * Resolves `hostname` once, validates every returned address, and returns a target
 * pinned to one validated IP. Rejects if ANY resolved address is blocked (per the
 * security skill's control flow) — a host that resolves to a mix of public and
 * private addresses is refused outright rather than trusting resolver ordering.
 */
export async function resolveAndPin(
  hostname: string,
  allowLocal: boolean
): Promise<PinnedTarget> {
  let addresses: LookupAddress[];
  try {
    addresses = await dnsLookup(hostname, { all: true });
  } catch {
    throw new ResolutionError(`Refused: could not resolve host "${hostname}".`);
  }

  if (addresses.length === 0) {
    throw new ResolutionError(`Refused: host "${hostname}" resolved to no addresses.`);
  }

  for (const addr of addresses) {
    // Link-local / cloud metadata is never bypassable, even with ALLOW_LOCAL=true.
    if (isAlwaysBlockedIp(addr.address)) {
      throw new ResolutionError(
        `Refused: "${hostname}" resolved to link-local/metadata address ${addr.address}. ` +
          "This is never allowed, regardless of SAFE_FETCH_ALLOW_LOCAL."
      );
    }
  }

  if (!allowLocal) {
    for (const addr of addresses) {
      if (isBlockedIp(addr.address)) {
        throw new ResolutionError(
          `Refused: "${hostname}" resolved to disallowed address ${addr.address}. ` +
            "Set SAFE_FETCH_ALLOW_LOCAL=true only for trusted local targets."
        );
      }
    }
  }

  const chosen = addresses[0];
  if (!chosen) {
    throw new ResolutionError(`Refused: host "${hostname}" resolved to no addresses.`);
  }
  const pinnedIp = chosen.address;
  const family = chosen.family as 4 | 6;

  const lookup: LookupFunction = (
    _host: string,
    options: LookupOptions,
    callback: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void
  ) => {
    // Node's HTTP client requests { all: true } when Happy Eyeballs
    // (autoSelectFamily) is active and expects an array back in that case — a bare
    // string is silently misread, surfacing as "Invalid IP address: undefined"
    // deep in the TLS/socket layer. Always match the shape the caller asked for.
    if (options.all) {
      callback(null, [{ address: pinnedIp, family }]);
    } else {
      callback(null, pinnedIp, family);
    }
  };

  return { hostname, pinnedIp, family, lookup };
}
