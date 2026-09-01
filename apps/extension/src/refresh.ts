/**
 * When to refresh, given the two independent expiries we track.
 *
 * The access token and the POP session expire on their own schedules, and
 * whichever lapses first breaks access — the token stops buying a new session,
 * or the proxy secret stops being accepted. So we always target the earlier of
 * the two, minus a margin so a slow network does not strand the browser with a
 * credential that expires mid-request.
 *
 * The floor matters as much as the margin: a token that is already expired (or
 * expires within the margin) would otherwise schedule an alarm in the past,
 * which Chrome fires immediately, producing a refresh loop that hammers the
 * IdP.
 */
export const REFRESH_MARGIN_MS = 60_000;
export const MIN_REFRESH_DELAY_MS = 30_000;

export function nextRefreshAt(
  tokenExpiresAt: number,
  sessionExpiresAt: number,
  now: number = Date.now(),
): number {
  const earliest = Math.min(tokenExpiresAt, sessionExpiresAt);
  return Math.max(now + MIN_REFRESH_DELAY_MS, earliest - REFRESH_MARGIN_MS);
}
