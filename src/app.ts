import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createToken, RequestError } from './token.js';

const MAX_BODY_BYTES = 16 * 1024;
const assets = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
  ['/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/styles.css', ['styles.css', 'text/css; charset=utf-8']],
]);

function json(response: ServerResponse, status: number, value: unknown) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(value));
}

async function readJson(request: IncomingMessage): Promise<unknown> {
  if (request.headers['content-type']?.split(';')[0]?.trim().toLowerCase() !== 'application/json') {
    throw new RequestError('Send the request as application/json.', 415);
  }
  const length = Number(request.headers['content-length']);
  if (Number.isFinite(length) && length > MAX_BODY_BYTES) {
    throw new RequestError('Request body must be smaller than 16 KB.', 413);
  }
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        chunks.length = 0;
        reject(new RequestError('Request body must be smaller than 16 KB.', 413));
        return;
      }
      chunks.push(chunk);
    });
    request.once('end', () => {
      if (size > MAX_BODY_BYTES) return;
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown);
      } catch {
        reject(new RequestError('Request body must contain valid JSON.'));
      }
    });
    request.once('error', reject);
    request.once('aborted', () => reject(new RequestError('Request was interrupted.')));
  });
}

export function createApp() {
  // A single local utility needs no per-user state or persistent storage.
  let windowStart = Date.now();
  let requests = 0;
  return createServer({ requestTimeout: 10_000, headersTimeout: 10_000 }, async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'");

    try {
      const url = new URL(request.url ?? '/', `http://${request.headers.host ?? 'localhost'}`);
      if (!['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) {
        throw new RequestError('This tool accepts requests on localhost only.', 403);
      }
      if (url.pathname === '/api/tokens') {
        if (request.method !== 'POST') {
          response.setHeader('Allow', 'POST');
          throw new RequestError('Use POST to generate a token.', 405);
        }
        if (request.headers['sec-fetch-site'] === 'cross-site' ||
            (request.headers.origin && request.headers.origin !== url.origin)) {
          throw new RequestError('Cross-origin requests are not allowed.', 403);
        }
        if (Date.now() - windowStart >= 60_000) {
          windowStart = Date.now();
          requests = 0;
        }
        if (++requests > 60) {
          response.setHeader('Retry-After', Math.ceil((windowStart + 60_000 - Date.now()) / 1000));
          throw new RequestError('Too many requests. Please try again in a minute.', 429);
        }
        json(response, 200, await createToken(await readJson(request)));
        return;
      }
      const asset = assets.get(url.pathname);
      if (!asset) throw new RequestError('Not found.', 404);
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        response.setHeader('Allow', 'GET, HEAD');
        throw new RequestError('Method not allowed.', 405);
      }
      const [filename, contentType] = asset;
      const body = await readFile(new URL(`../public/${filename}`, import.meta.url));
      response.writeHead(200, { 'Content-Type': contentType! });
      response.end(request.method === 'HEAD' ? undefined : body);
    } catch (error) {
      if (response.destroyed) return;
      if (error instanceof RequestError) {
        // Close rejected connections so unread bodies cannot be reused.
        response.setHeader('Connection', 'close');
        json(response, error.status, { error: error.message });
      } else {
        json(response, 500, { error: 'Unable to process the request. Please try again.' });
      }
    }
  });
}
