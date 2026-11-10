const form = document.querySelector('#token-form');
const secret = document.querySelector('#secret');
const claims = document.querySelector('#claims');
const error = document.querySelector('#form-error');
const submitButton = document.querySelector('#generate-token');
const copyButton = document.querySelector('#copy-token');
const status = document.querySelector('#app-status');
let currentToken = '';
let pending = false;

function showError(message) {
  error.textContent = message;
  error.hidden = false;
}

function parseClaims() {
  let parsed;
  try {
    parsed = JSON.parse(claims.value.trim() || '{}');
  } catch {
    throw new Error('Custom claims must contain valid JSON. Check for missing quotes or trailing commas.');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Custom claims must be a JSON object, such as { "role": "developer" }.');
  }
  return parsed;
}

function clearResult() {
  currentToken = '';
  document.querySelector('#token-result').hidden = true;
  document.querySelector('#empty-state').hidden = false;
  document.querySelector('#result-badge').textContent = 'Ready when you are';
  document.querySelector('#result-badge').classList.remove('is-generated');
  for (const id of ['#token', '#decoded-header', '#decoded-payload', '#token-meta', '#copy-status']) {
    document.querySelector(id).textContent = '';
  }
  copyButton.textContent = 'Copy token';
}

form.addEventListener('input', () => {
  error.hidden = true;
  clearResult();
});

document.querySelector('#generate-secret').addEventListener('click', () => {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  secret.value = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  secret.dispatchEvent(new Event('input', { bubbles: true }));
  status.textContent = 'A random 256-bit signing secret has been generated.';
});

document.querySelector('#toggle-secret').addEventListener('click', (event) => {
  const show = secret.type === 'password';
  secret.type = show ? 'text' : 'password';
  event.currentTarget.textContent = show ? 'Hide' : 'Show';
  event.currentTarget.setAttribute('aria-label', show ? 'Hide signing secret' : 'Show signing secret');
  event.currentTarget.setAttribute('aria-pressed', String(show));
});

document.querySelector('#format-claims').addEventListener('click', () => {
  error.hidden = true;
  try {
    claims.value = JSON.stringify(parseClaims(), null, 2);
    status.textContent = 'Custom claims formatted.';
  } catch (cause) {
    showError(cause.message);
    claims.focus();
  }
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (pending) return;
  error.hidden = true;
  clearResult();
  try {
    const customClaims = parseClaims();
    const secretBytes = new TextEncoder().encode(secret.value).byteLength;
    if (secretBytes < 32 || secretBytes > 4096) {
      secret.focus();
      throw new Error('Signing secret must be between 32 and 4096 UTF-8 bytes. Use Generate secret for a random key.');
    }
    const data = new FormData(form);
    const body = JSON.stringify({
      subject: data.get('subject'), issuer: data.get('issuer'), audience: data.get('audience'),
      expiresIn: Number(data.get('expiresIn')), claims: customClaims, secret: secret.value,
    });
    pending = true;
    submitButton.disabled = true;
    submitButton.textContent = 'Generating…';
    // Freeze the fields so the displayed token always matches the submitted values.
    const controls = Array.from(form.querySelectorAll('input, select, textarea, button'));
    controls.forEach((control) => { control.disabled = true; });
    try {
      const response = await fetch('/api/tokens', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
        signal: AbortSignal.timeout(15000),
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Unable to generate the token. Please try again.');
      currentToken = result.token;
      const tokenElement = document.querySelector('#token');
      currentToken.split('.').forEach((part, index) => {
        if (index) tokenElement.append(document.createTextNode('.'));
        const span = document.createElement('span');
        span.className = ['jwt-header', 'jwt-payload', 'jwt-signature'][index];
        span.textContent = part;
        tokenElement.append(span);
      });
      document.querySelector('#decoded-header').textContent = JSON.stringify(result.header, null, 2);
      document.querySelector('#decoded-payload').textContent = JSON.stringify(result.payload, null, 2);
      document.querySelector('#token-meta').textContent = `${currentToken.length} characters · Expires ${new Date(result.expiresAt * 1000).toLocaleString()}`;
      document.querySelector('#empty-state').hidden = true;
      document.querySelector('#token-result').hidden = false;
      document.querySelector('#result-badge').textContent = 'Token generated';
      document.querySelector('#result-badge').classList.add('is-generated');
      status.textContent = 'Token generated. Your signed token and decoded claims are ready.';
    } finally {
      controls.forEach((control) => { control.disabled = false; });
    }
  } catch (cause) {
    const message = cause.name === 'TimeoutError' ? 'The request timed out. Please try again.'
      : cause instanceof TypeError ? 'Cannot reach the server. Check that it is running, then try again.'
        : cause.message;
    showError(message);
  } finally {
    pending = false;
    submitButton.disabled = false;
    submitButton.replaceChildren(document.createTextNode('Generate token '));
    const arrow = document.createElement('span');
    arrow.setAttribute('aria-hidden', 'true');
    arrow.textContent = '→';
    submitButton.append(arrow);
  }
});

copyButton.addEventListener('click', async () => {
  if (!currentToken) return;
  try {
    await navigator.clipboard.writeText(currentToken);
    copyButton.textContent = 'Copied!';
    document.querySelector('#copy-status').textContent = 'Token copied to clipboard.';
  } catch {
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(document.querySelector('#token'));
    selection.removeAllRanges();
    selection.addRange(range);
    document.querySelector('#copy-status').textContent = 'Clipboard unavailable. Token selected; press Ctrl+C or ⌘C to copy.';
  }
});
