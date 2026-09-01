import type { PopSession } from './types.js';

/**
 * True only when a proxy auth challenge came from the POP this session was
 * issued for.
 *
 * `details.isProxy` tells us a proxy issued the challenge — not which one.
 * The proxy secret authorizes access to every app the user can reach, so
 * handing it to whoever asks would let another extension's PAC, a system
 * proxy, or a network attacker able to force a 407 collect it.
 */
export function isOurProxy(
  challenger: { host: string; port: number } | undefined,
  session: PopSession,
): boolean {
  if (!challenger) return false;
  return (
    challenger.host.toLowerCase() === session.proxy.host.toLowerCase() &&
    challenger.port === session.proxy.port
  );
}
