import { lookup as dnsLookup } from "node:dns/promises";
import type { LookupAddress, LookupOptions } from "node:dns";
import type { LookupFunction } from "node:net";
import { isBlockedIp, isAlwaysBlockedIp } from "./ipGuard.js";
import { GuardError } from "./errors.js";

/**
 * Messages are shown to the calling model, so they never include resolved
 * addresses (that would turn refusals into an internal-DNS oracle). The resolved
 * address goes in `cause`, which only the stderr audit log prints.
 */
export class ResolutionError extends GuardError {}

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

/** Resolves a hostname to every A/AAAA answer. Injectable so tests can fake DNS. */
export type Resolver = (hostname: string) => Promise<LookupAddress[]>;

export const systemResolver: Resolver = (hostname) => dnsLookup(hostname, { all: true });

/**
 * Resolves `hostname` once, validates every returned address, and returns a target
 * pinned to one validated IP. Rejects if ANY resolved address is blocked (per the
 * security skill's control flow) — a host that resolves to a mix of public and
 * private addresses is refused outright rather than trusting resolver ordering.
 */
export async function resolveAndPin(
  hostname: string,
  allowLocal: boolean,
  resolve: Resolver = systemResolver
): Promise<PinnedTarget> {
  let addresses: LookupAddress[];
  try {
    addresses = await resolve(hostname);
  } catch (err) {
    throw new ResolutionError(
      "DNS_RESOLUTION_FAILED",
      `Refused: could not resolve host "${hostname}".`,
      {
        cause: err instanceof Error ? err.message : String(err)
      }
    );
  }

  if (addresses.length === 0) {
    throw new ResolutionError(
      "DNS_RESOLUTION_FAILED",
      `Refused: host "${hostname}" resolved to no addresses.`
    );
  }

  for (const addr of addresses) {
    // Link-local / cloud metadata is never bypassable, even with ALLOW_LOCAL=true.
    if (isAlwaysBlockedIp(addr.address)) {
      throw new ResolutionError(
        "POLICY_REJECTED",
        `Refused: "${hostname}" resolves to a cloud-metadata, link-local or reserved ` +
          "address. This is never allowed, regardless of SAFE_FETCH_ALLOW_LOCAL.",
        { cause: `resolved address=${addr.address}` }
      );
    }
  }

  if (!allowLocal) {
    for (const addr of addresses) {
      if (isBlockedIp(addr.address)) {
        throw new ResolutionError(
          "POLICY_REJECTED",
          `Refused: "${hostname}" resolves to a private or non-public address. ` +
            "Set SAFE_FETCH_ALLOW_LOCAL=true only for trusted local targets.",
          { cause: `resolved address=${addr.address}` }
        );
      }
    }
  }

  const chosen = addresses[0];
  if (!chosen) {
    throw new ResolutionError(
      "DNS_RESOLUTION_FAILED",
      `Refused: host "${hostname}" resolved to no addresses.`
    );
  }
  const pinnedIp = chosen.address;
  const family = chosen.family as 4 | 6;

  const lookup: LookupFunction = (
    _host: string,
    options: LookupOptions,
    callback: (
      err: NodeJS.ErrnoException | null,
      address: string | LookupAddress[],
      family?: number
    ) => void
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
