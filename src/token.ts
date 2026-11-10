import { SignJWT } from 'jose';

export class RequestError extends Error {
  constructor(message: string, public readonly status = 400) {
    super(message);
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function optionalClaim(value: unknown, name: string): string | undefined {
  if (value === undefined || value === '') return undefined;
  if (typeof value !== 'string' || value.length > 512 || !value.trim()) {
    throw new RequestError(`${name} must be a non-empty string of at most 512 characters.`);
  }
  return value.trim();
}

export async function createToken(input: unknown) {
  if (!isObject(input)) throw new RequestError('Request body must be a JSON object.');

  const allowed = ['secret', 'subject', 'issuer', 'audience', 'expiresIn', 'claims'];
  if (Object.keys(input).some((key) => !allowed.includes(key))) {
    throw new RequestError('Request contains an unsupported field. The signing algorithm is HS256.');
  }
  if (typeof input.secret !== 'string') throw new RequestError('A signing secret is required.');
  const secret = new TextEncoder().encode(input.secret);
  if (secret.byteLength < 32 || secret.byteLength > 4096) {
    throw new RequestError('Signing secret must be between 32 and 4096 UTF-8 bytes.');
  }
  if (!Number.isInteger(input.expiresIn) || typeof input.expiresIn !== 'number' ||
      input.expiresIn < 60 || input.expiresIn > 604800) {
    throw new RequestError('Expiration must be a whole number from 60 to 604800 seconds.');
  }
  if (input.claims !== undefined && !isObject(input.claims)) {
    throw new RequestError('Custom claims must be a JSON object.');
  }
  const claims = input.claims ?? {};
  const reserved = ['sub', 'iss', 'aud', 'iat', 'exp', 'nbf'];
  if (Object.keys(claims).some((key) => reserved.includes(key))) {
    throw new RequestError('Use the form fields for sub, iss, and aud. The server manages iat and exp; nbf is not supported.');
  }

  const subject = optionalClaim(input.subject, 'Subject');
  const issuer = optionalClaim(input.issuer, 'Issuer');
  const audience = optionalClaim(input.audience, 'Audience');
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + input.expiresIn;
  const payload = {
    ...claims,
    ...(subject ? { sub: subject } : {}),
    ...(issuer ? { iss: issuer } : {}),
    ...(audience ? { aud: audience } : {}),
    iat: issuedAt,
    exp: expiresAt,
  };
  const header = { alg: 'HS256', typ: 'JWT' };
  const token = await new SignJWT(payload).setProtectedHeader(header).sign(secret);
  return { token, header, payload, expiresAt };
}
