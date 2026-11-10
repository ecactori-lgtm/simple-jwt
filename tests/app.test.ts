import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { after, before, describe, it } from 'node:test';
import { once } from 'node:events';
import { jwtVerify } from 'jose';
import { createApp } from '../src/app.js';

const secret = 'a-disposable-test-key-with-at-least-32-bytes';
const validInput = {
  secret, subject: 'user_123', issuer: 'test-app', audience: 'test-api',
  expiresIn: 3600, claims: { name: 'Alex', admin: false, roles: ['reader'], profile: { locale: '日本語' } },
};

async function start() {
  const server = createApp();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  assert(address && typeof address !== 'string');
  return { server, base: `http://127.0.0.1:${address.port}` };
}

describe('JWT generator HTTP API', () => {
  let app: Awaited<ReturnType<typeof start>>;
  before(async () => { app = await start(); });
  after(async () => {
    app.server.closeAllConnections();
    await new Promise<void>((resolve, reject) => app.server.close((error) => error ? reject(error) : resolve()));
  });

  function post(body: unknown, headers: Record<string, string> = {}) {
    return fetch(`${app.base}/api/tokens`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body),
    });
  }

  it('creates an independently verifiable HS256 token with exact claims and lifetime', async () => {
    const response = await post(validInput);
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    const result = await response.json();
    assert.equal('secret' in result, false);
    assert.equal('secret' in result.payload, false);
    const [header, payload, signature] = result.token.split('.');
    const expected = createHmac('sha256', secret).update(`${header}.${payload}`).digest('base64url');
    assert.equal(signature, expected);
    assert.deepEqual(JSON.parse(Buffer.from(header, 'base64url').toString()), { alg: 'HS256', typ: 'JWT' });
    assert.deepEqual(JSON.parse(Buffer.from(payload, 'base64url').toString()), result.payload);
    const verified = await jwtVerify(result.token, new TextEncoder().encode(secret), {
      algorithms: ['HS256'], issuer: validInput.issuer, audience: validInput.audience, subject: validInput.subject,
    });
    assert.deepEqual(verified.payload, result.payload);
    assert.equal(result.payload.exp - result.payload.iat, 3600);
    assert.equal(result.expiresAt, result.payload.exp);
    assert(Math.abs(result.payload.iat - Math.floor(Date.now() / 1000)) <= 1);
    assert.deepEqual(result.payload.profile, { locale: '日本語' });
    assert.deepEqual(result.payload.roles, ['reader']);
    assert.equal(result.payload.admin, false);
    await assert.rejects(jwtVerify(result.token, new TextEncoder().encode('wrong-key-with-at-least-32-characters')));
    const tamperedPayload = Buffer.from(JSON.stringify({ ...result.payload, admin: true })).toString('base64url');
    await assert.rejects(jwtVerify(`${header}.${tamperedPayload}.${signature}`, new TextEncoder().encode(secret)));
  });

  it('supports minimal input, boundary expirations, and same-origin browser requests', async () => {
    for (const expiresIn of [60, 604800]) {
      const response = await post({ secret, expiresIn }, { Origin: app.base });
      assert.equal(response.status, 200);
      const { payload } = await response.json();
      assert.deepEqual(Object.keys(payload).sort(), ['exp', 'iat']);
      assert.equal(payload.exp - payload.iat, expiresIn);
    }
  });

  it('rejects invalid input without returning secrets', async () => {
    const invalid = [
      null, [], 'text', {},
      { ...validInput, secret: 'short' },
      { ...validInput, secret: 'x'.repeat(4097) },
      { ...validInput, secret: 123 },
      { ...validInput, expiresIn: 59 },
      { ...validInput, expiresIn: 604801 },
      { ...validInput, expiresIn: 60.5 },
      { ...validInput, expiresIn: '3600' },
      { ...validInput, subject: false },
      { ...validInput, issuer: ' ' },
      { ...validInput, audience: 'x'.repeat(513) },
      { ...validInput, claims: [] },
      { ...validInput, claims: null },
      { ...validInput, claims: 'oops' },
      { ...validInput, algorithm: 'none' },
      ...['sub', 'iss', 'aud', 'exp', 'iat', 'nbf'].map((claim) => ({ ...validInput, claims: { [claim]: 'override' } })),
    ];
    for (const input of invalid) {
      const response = await post(input);
      assert.equal(response.status, 400, JSON.stringify(input));
      const result = await response.json();
      assert.equal(typeof result.error, 'string');
      assert.equal(JSON.stringify(result).includes(secret), false);
      assert.equal('token' in result, false);
    }
  });

  it('rejects malformed JSON, incorrect content types, and oversized bodies', async () => {
    const malformed = await fetch(`${app.base}/api/tokens`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{broken',
    });
    assert.equal(malformed.status, 400);
    const wrongType = await post(validInput, { 'Content-Type': 'text/plain' });
    assert.equal(wrongType.status, 415);
    const oversized = await post({ ...validInput, claims: { big: 'x'.repeat(17000) } });
    assert.equal(oversized.status, 413);
    // Exercise the streaming limit with no Content-Length header as well.
    const chunkedStatus = await new Promise<number | undefined>((resolve, reject) => {
      const request = httpRequest(`${app.base}/api/tokens`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
      }, (response) => { response.resume(); resolve(response.statusCode); });
      request.on('error', reject);
      request.write('{"big":"');
      request.write('x'.repeat(17000));
      request.end('"}');
    });
    assert.equal(chunkedStatus, 413);
  });

  it('rejects cross-origin requests and non-local hostnames', async () => {
    assert.equal((await post(validInput, { Origin: 'https://example.com' })).status, 403);
    assert.equal((await post(validInput, { 'Sec-Fetch-Site': 'cross-site' })).status, 403);
    assert.equal((await post(validInput, { Host: 'example.com' })).status, 403);
  });

  it('serves only public assets with security headers and correct methods', async () => {
    for (const [path, type] of [['/', 'text/html'], ['/app.js', 'text/javascript'], ['/styles.css', 'text/css']]) {
      const response = await fetch(`${app.base}${path}`);
      assert.equal(response.status, 200);
      assert(response.headers.get('content-type')?.startsWith(type!));
      assert(response.headers.get('content-security-policy')?.includes("script-src 'self'"));
      assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
      assert.equal(response.headers.get('x-frame-options'), 'DENY');
      assert((await response.text()).length > 0);
    }
    for (const path of ['/src/token.ts', '/package.json', '/.env', '/nonexistent']) {
      assert.equal((await fetch(`${app.base}${path}`)).status, 404);
    }
    const head = await fetch(app.base, { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(await head.text(), '');
    const apiGet = await fetch(`${app.base}/api/tokens`);
    assert.equal(apiGet.status, 405);
    assert.equal(apiGet.headers.get('allow'), 'POST');
    assert.equal((await fetch(app.base, { method: 'POST' })).status, 405);
  });
});

it('limits token generation requests', async () => {
  const app = await start();
  try {
    for (let index = 0; index < 60; index++) {
      const response = await fetch(`${app.base}/api/tokens`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret, expiresIn: 60 }),
      });
      assert.equal(response.status, 200);
      await response.arrayBuffer();
    }
    const response = await fetch(`${app.base}/api/tokens`, { method: 'POST' });
    assert.equal(response.status, 429);
    assert(Number(response.headers.get('retry-after')) > 0);
    await response.arrayBuffer();
  } finally {
    app.server.closeAllConnections();
    await new Promise<void>((resolve, reject) => app.server.close((error) => error ? reject(error) : resolve()));
  }
});
