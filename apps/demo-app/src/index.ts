import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';

/**
 * A stand-in private application. It is never published to the host: the only
 * way to reach it is through the connector, so the headers it echoes back are
 * direct evidence that the request actually traversed the tunnel.
 */

const HTTP_PORT = Number(process.env.HTTP_PORT ?? 80);
const HTTPS_PORT = Number(process.env.HTTPS_PORT ?? 443);
const APP_NAME = process.env.APP_NAME ?? 'Internal App';
const ACCENT = process.env.APP_ACCENT ?? '#3b6ea5';
const CERT_FILE = process.env.TLS_CERT_FILE;
const KEY_FILE = process.env.TLS_KEY_FILE;

const handler = (req: http.IncomingMessage, res: http.ServerResponse): void => {
  const headers = Object.entries(req.headers)
    .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td></tr>`)
    .join('\n');

  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(`<!doctype html>
<meta charset="utf-8">
<title>${escapeHtml(APP_NAME)}</title>
<style>
  body { font: 15px/1.6 system-ui, sans-serif; max-width: 46rem; margin: 4rem auto; padding: 0 1.5rem; color: #16202c; }
  .badge { display: inline-block; background: ${ACCENT}; color: #fff; padding: .3rem .7rem; border-radius: 999px; font-size: .8rem; font-weight: 600; letter-spacing: .02em; }
  h1 { margin: .8rem 0 .2rem; font-size: 1.9rem; }
  p.lede { color: #5a6b7d; margin-top: 0; }
  table { border-collapse: collapse; width: 100%; margin-top: 1.5rem; font-size: .85rem; }
  td { border-top: 1px solid #e3e8ee; padding: .45rem .6rem; vertical-align: top; }
  td:first-child { color: #5a6b7d; white-space: nowrap; width: 14rem; font-family: ui-monospace, monospace; }
  code { background: #eef2f6; padding: .12rem .35rem; border-radius: 4px; }
</style>
<span class="badge">PRIVATE NETWORK</span>
<h1>${escapeHtml(APP_NAME)}</h1>
<p class="lede">
  Served by <code>${escapeHtml(os.hostname())}</code>.
  This host has no published ports &mdash; if you can read this, the request
  arrived through the ZTNA tunnel.
</p>
<p>Request: <code>${escapeHtml(req.method ?? '')} ${escapeHtml(req.url ?? '')}</code>
  over <code>${(req.socket as { encrypted?: boolean }).encrypted ? 'HTTPS' : 'HTTP'}</code></p>
<table><tbody>${headers}</tbody></table>
`);
};

http.createServer(handler).listen(HTTP_PORT, '0.0.0.0', () => {
  console.log(JSON.stringify({ msg: 'demo app listening (http)', app: APP_NAME, port: HTTP_PORT }));
});

/*
 * Serving real TLS here is the point, not decoration. The browser completes a
 * TLS handshake with THIS host through the tunnel, so the POP only ever sees
 * an opaque CONNECT stream — it never holds the plaintext of app traffic.
 */
if (CERT_FILE && KEY_FILE) {
  https
    .createServer({ cert: fs.readFileSync(CERT_FILE), key: fs.readFileSync(KEY_FILE) }, handler)
    .listen(HTTPS_PORT, '0.0.0.0', () => {
      console.log(
        JSON.stringify({ msg: 'demo app listening (https)', app: APP_NAME, port: HTTPS_PORT }),
      );
    });
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c,
  );
}
