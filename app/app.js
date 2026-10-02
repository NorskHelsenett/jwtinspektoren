'use strict';

const $ = (id) => document.getElementById(id);
const input = $('token');

const keyInput = $('key');
const verifyResult = $('verify-result');
let current = null;
let verifySeq = 0;

function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function base64UrlToBytes(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  b64 += '='.repeat((4 - (b64.length % 4)) % 4);
  return base64ToBytes(b64);
}

function base64UrlDecode(str) {
  return new TextDecoder('utf-8', { fatal: true }).decode(base64UrlToBytes(str));
}

function decodePart(part, name) {
  try {
    return JSON.parse(base64UrlDecode(part));
  } catch {
    throw new Error(`Ugyldig ${name}: ikke base64url-kodet JSON`);
  }
}

function decodeJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error(`Forventet 3 deler adskilt med '.', fikk ${parts.length}`);
  }
  return {
    header: decodePart(parts[0], 'header'),
    payload: decodePart(parts[1], 'payload'),
    signature: parts[2],
    signingInput: `${parts[0]}.${parts[1]}`,
  };
}

function algParams(alg) {
  const m = /^(RS|PS|ES|HS)(256|384|512)$/.exec(alg);
  if (alg === 'EdDSA') {
    return { kind: 'Ed', importAlg: { name: 'Ed25519' }, verifyAlg: { name: 'Ed25519' } };
  }
  if (!m) throw new Error(`Algoritmen støttes ikke eller er usikker: ${alg}`);
  const hash = `SHA-${m[2]}`;
  switch (m[1]) {
    case 'RS':
      return { kind: 'RS', importAlg: { name: 'RSASSA-PKCS1-v1_5', hash }, verifyAlg: { name: 'RSASSA-PKCS1-v1_5' } };
    case 'PS':
      return { kind: 'PS', importAlg: { name: 'RSA-PSS', hash }, verifyAlg: { name: 'RSA-PSS', saltLength: m[2] / 8 } };
    case 'ES': {
      const namedCurve = { 256: 'P-256', 384: 'P-384', 512: 'P-521' }[m[2]];
      return { kind: 'ES', importAlg: { name: 'ECDSA', namedCurve }, verifyAlg: { name: 'ECDSA', hash } };
    }
    default:
      return { kind: 'HS', importAlg: { name: 'HMAC', hash }, verifyAlg: { name: 'HMAC' } };
  }
}

async function importKey(format, data, params) {
  try {
    return await crypto.subtle.importKey(format, data, params.importAlg, false, ['verify']);
  } catch {
    throw new Error(`Nøkkelen kan ikke brukes med ${params.importAlg.name}${params.importAlg.namedCurve ? ` ${params.importAlg.namedCurve}` : ''}`);
  }
}

// Returns candidate CryptoKeys for the given user-supplied key text.
async function keysFromText(text, header, params) {
  const trimmed = text.trim();

  if (trimmed.startsWith('-----BEGIN CERTIFICATE')) {
    throw new Error('X.509-sertifikater støttes ikke; lim inn den offentlige nøkkelen (BEGIN PUBLIC KEY) eller en JWK');
  }
  const pem = /^-----BEGIN PUBLIC KEY-----([\s\S]+)-----END PUBLIC KEY-----$/.exec(trimmed);
  if (pem) {
    return [await importKey('spki', base64ToBytes(pem[1].replace(/\s+/g, '')), params)];
  }
  if (trimmed.startsWith('-----BEGIN')) {
    throw new Error('PEM-typen støttes ikke; forventet BEGIN PUBLIC KEY');
  }

  if (trimmed.startsWith('{')) {
    let json;
    try {
      json = JSON.parse(trimmed);
    } catch {
      throw new Error('Nøkkelen ser ut som JSON, men kunne ikke tolkes');
    }
    return (await keysFromJwks(Array.isArray(json.keys) ? json : { keys: [json] }, header, params)).keys;
  }

  if (params.kind !== 'HS') {
    throw new Error(`${header.alg} krever en offentlig nøkkel (JWK, JWKS eller PEM), ikke en hemmelighet`);
  }
  return [await importKey('raw', new TextEncoder().encode(text), params)];
}

async function keysFromJwks(jwks, header, params) {
  let candidates = jwks.keys;
  if (header.kid) {
    candidates = candidates.filter((k) => k.kid === header.kid);
    if (!candidates.length) throw new Error(`Fant ingen nøkkel med kid "${header.kid}" (utstederen kan ha rotert nøklene sine)`);
  }
  const keys = [];
  const used = [];
  for (const jwk of candidates) {
    if (jwk.alg && jwk.alg !== header.alg) continue;
    try {
      const { use, key_ops, ...clean } = jwk;
      keys.push(await importKey('jwk', clean, params));
      used.push(jwk);
    } catch {
      // Key type does not match the token's algorithm.
    }
  }
  if (!keys.length) throw new Error(`Ingen brukbar nøkkel for algoritmen ${header.alg}`);
  return { keys, used };
}

async function verifyWith(keys, params) {
  const sig = base64UrlToBytes(current.signature);
  const data = new TextEncoder().encode(current.signingInput);
  for (const key of keys) {
    if (await crypto.subtle.verify(params.verifyAlg, key, sig, data)) return true;
  }
  return false;
}

async function fetchJson(url, manualHint) {
  let res;
  try {
    res = await fetch(url, { credentials: 'omit', referrerPolicy: 'no-referrer' });
  } catch {
    // fetch() hides the cause (CORS, DNS, firewall) from JavaScript by design.
    const err = new Error(
      `Klarte ikke å hente ${url}. Årsaken kan være brannmur/nettverk, eller at utstederen ikke tillater CORS ` +
      '(mangler Access-Control-Allow-Origin). Detaljer finnes i nettleserens utviklerkonsoll.',
    );
    err.link = { url, hint: manualHint };
    throw err;
  }
  if (!res.ok) throw new Error(`${url} svarte med HTTP ${res.status}`);
  return res.json();
}

function requireHttps(url, what) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`${what} er ikke en gyldig URL`);
  }
  if (parsed.protocol !== 'https:') throw new Error(`${what} må bruke https`);
  return parsed.href.replace(/\/$/, '');
}

function showVerify(state, title, detail = '', link = null) {
  const icons = { pending: '…', ok: '\u2714', bad: '\u2718', error: '!' };
  $('verify-icon').textContent = icons[state];
  $('verify-title').textContent = title;
  $('verify-detail').textContent = detail;
  const linkEl = $('verify-link');
  linkEl.hidden = !link;
  if (link) {
    $('verify-link-hint').textContent = link.hint;
    const a = $('verify-link-a');
    a.href = link.url;
    a.textContent = link.url;
  }
  verifyResult.className = `badge ${state}`;
  verifyResult.hidden = false;
}

async function runVerify(getKeys) {
  if (!current) return;
  const seq = ++verifySeq;
  const ctx = {};
  showVerify('pending', 'Verifiserer...');
  try {
    const params = algParams(current.header.alg);
    const { keys, source } = await getKeys(params, ctx);
    const ok = await verifyWith(keys, params);
    if (seq !== verifySeq) return;
    showVerify(ok ? 'ok' : 'bad', ok ? 'Gyldig signatur' : 'UGYLDIG signatur', `${current.header.alg}, ${source}`);
  } catch (e) {
    if (seq !== verifySeq) return;
    showVerify('error', 'Kunne ikke verifisere signaturen', e.message, e.link);
  }
  if (seq === verifySeq && ctx.keyText) keyInput.value = ctx.keyText;
}

function verifyWithPastedKey() {
  if (!keyInput.value.trim()) {
    verifySeq++;
    verifyResult.hidden = true;
    return;
  }
  runVerify(async (params) => ({
    keys: await keysFromText(keyInput.value, current.header, params),
    source: 'innlimt nøkkel',
  }));
}

function verifyWithIssuer() {
  const { header, payload } = current;
  runVerify(async (params, ctx) => {
    if (typeof payload.iss !== 'string') throw new Error('Tokenet har ingen iss-claim');
    const iss = requireHttps(payload.iss, 'Utsteder');
    const config = await fetchJson(
      `${iss}/.well-known/openid-configuration`,
      'Hent manuelt: åpne lenken, finn jwks_uri, åpne den og lim inn JSON-innholdet i nøkkelfeltet.',
    );
    const jwksUri = requireHttps(config.jwks_uri, 'jwks_uri');
    const jwks = await fetchJson(jwksUri, 'Hent manuelt: åpne lenken og lim inn JSON-innholdet i nøkkelfeltet.');
    // Show the full key set if no matching key is found, so the user can inspect it.
    ctx.keyText = JSON.stringify(jwks, null, 2);
    const { keys, used } = await keysFromJwks(jwks, header, params);
    ctx.keyText = JSON.stringify(used.length === 1 ? used[0] : { keys: used }, null, 2);
    return { keys, source: `nøkkel fra ${jwksUri}` };
  });
}

function formatTime(seconds) {
  const d = new Date(seconds * 1000);
  const p = (n) => String(n).padStart(2, '0');
  // Offset is per date, so DST is reflected correctly.
  const offset = -d.getTimezoneOffset();
  const sign = offset < 0 ? '-' : '+';
  const abs = Math.abs(offset);
  const zone = offset === 0 ? 'UTC' : `UTC${sign}${Math.floor(abs / 60)}${abs % 60 ? `:${p(abs % 60)}` : ''}`;
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())} ` +
    `${p(d.getDate())}.${p(d.getMonth() + 1)}.${d.getFullYear()} (${zone})`;
}

function renderClaims(payload) {
  const table = $('claims');
  table.replaceChildren();
  const now = Date.now() / 1000;
  const names = { iat: 'Utstedt', nbf: 'Ikke gyldig før', exp: 'Utløper' };
  let any = false;

  for (const [key, label] of Object.entries(names)) {
    if (typeof payload[key] !== 'number') continue;
    any = true;
    const row = table.insertRow();
    row.insertCell().textContent = `${label} (${key})`;
    const time = row.insertCell();
    time.textContent = formatTime(payload[key]);
    const status = row.insertCell();
    let ok;
    if (key === 'exp') {
      ok = payload.exp >= now;
      status.textContent = ok ? 'Ikke utløpt' : 'Utløpt';
    } else if (key === 'nbf') {
      ok = payload.nbf <= now;
      status.textContent = ok ? 'Passert' : 'Ikke gyldig ennå';
    } else {
      ok = payload.iat <= now;
      status.textContent = ok ? 'Passert' : 'I fremtiden';
    }
    status.className = time.className = ok ? 'valid' : 'expired';
  }
  $('claims-wrap').hidden = !any;
}

function render(raw) {
  const token = raw.trim().replace(/^Bearer\s+/i, '');
  const error = $('error');
  const output = $('output');

  current = null;
  verifySeq++;
  verifyResult.hidden = true;

  if (!token) {
    error.hidden = true;
    output.hidden = true;
    return;
  }

  try {
    current = decodeJwt(token);
    const { header, payload, signature } = current;
    $('header').textContent = JSON.stringify(header, null, 2);
    $('payload').textContent = JSON.stringify(payload, null, 2);
    $('signature').textContent = signature;
    renderClaims(payload);
    error.hidden = true;
    output.hidden = false;
    verifyWithPastedKey();
  } catch (e) {
    error.textContent = e.message;
    error.hidden = false;
    output.hidden = true;
  }
}

// Supports /<token>, /#<token> and ?token=<token>
function tokenFromUrl() {
  const hash = decodeURIComponent(location.hash.slice(1));
  if (hash) return hash;
  const query = new URLSearchParams(location.search).get('token');
  if (query) return query;
  return decodeURIComponent(location.pathname.replace(/^\/+/, '').replace(/\/+$/, ''));
}

function loadFromUrl() {
  const token = tokenFromUrl();
  if (token && token !== 'index.html') {
    input.value = token;
    render(token);
  }
}

input.addEventListener('input', () => render(input.value));
keyInput.addEventListener('input', verifyWithPastedKey);
$('verify-issuer').addEventListener('click', verifyWithIssuer);
window.addEventListener('hashchange', loadFromUrl);
loadFromUrl();
