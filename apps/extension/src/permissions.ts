/**
 * Why this extension declares `<all_urls>`.
 *
 * Answering the POP's 407 requires webRequest host access for the URL that
 * triggered it. Verified empirically: with the permission removed, sign-in,
 * the PAC install and the session all still succeed, but every request to a
 * protected host hangs with the challenge unanswered.
 *
 * It is declared rather than optional on purpose:
 *
 *  - There is no useful degraded mode. The extension's only function is
 *    reaching private apps, so a declined permission leaves it inert. Deferring
 *    the prompt does not reduce the access eventually granted, it only moves
 *    when it is asked for and adds a failure mode.
 *  - `chrome.permissions.request` opens a native prompt that cannot be driven
 *    by automation, which would cost the end-to-end browser test that covers
 *    the whole sign-in and tunnel flow.
 *  - ZTNA clients are force-installed by enterprise policy, where host access
 *    is granted by the administrator either way.
 *
 * NARROWING IT: the broad pattern is only needed because protected hostnames
 * come from policy at runtime. A deployment that knows its own app domains
 * should replace `<all_urls>` in manifest.json with just those — e.g.
 * `["https://*.corp.example.com/*"]`. Everything else here is unchanged.
 */
const REQUIRED_ORIGINS = ['<all_urls>'];

export async function hasHostAccess(): Promise<boolean> {
  return chrome.permissions.contains({ origins: REQUIRED_ORIGINS });
}
