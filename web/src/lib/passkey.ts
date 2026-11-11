// Passkeys for the vault, in the browser. A passkey signs in (WebAuthn) and,
// when the browser and authenticator can do the PRF extension, also unlocks:
// the passkey gives a secret only it can make again, which becomes a key
// that opens a private key, which opens the user key. Same scheme as
// Bitwarden's "log in with passkey", so the keys work the same way.
import { b64, decryptBytes, encryptBytes, stretch, SymKey } from './crypto'

const te = new TextEncoder()

export const passkeysAvailable = () => typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials

const b64u = {
  enc(buf: ArrayBuffer | Uint8Array): string { return b64.enc(buf instanceof Uint8Array ? buf : new Uint8Array(buf)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') },
  dec(s: string): Uint8Array { s = s.replace(/-/g, '+').replace(/_/g, '/'); return b64.dec(s + '='.repeat((4 - (s.length % 4)) % 4)) },
}

/** What the PRF is asked for: SHA-256("passwordless-login"), as Bitwarden does. */
async function prfSalt(): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode('passwordless-login')))
}

type Desc = { id: string; type: string; transports?: string[] }

function creationOptions(o: any, salt: Uint8Array): PublicKeyCredentialCreationOptions {
  return {
    ...o,
    challenge: b64u.dec(o.challenge) as BufferSource,
    user: { ...o.user, id: b64u.dec(o.user.id) as BufferSource },
    excludeCredentials: (o.excludeCredentials || []).map((c: Desc) => ({ ...c, id: b64u.dec(c.id) as BufferSource })),
    extensions: { ...(o.extensions || {}), prf: { eval: { first: salt as BufferSource } } } as AuthenticationExtensionsClientInputs,
  }
}

function requestOptions(o: any, salt: Uint8Array): PublicKeyCredentialRequestOptions {
  return {
    ...o,
    challenge: b64u.dec(o.challenge) as BufferSource,
    allowCredentials: (o.allowCredentials || []).map((c: Desc) => ({ ...c, id: b64u.dec(c.id) as BufferSource })),
    extensions: { ...(o.extensions || {}), prf: { eval: { first: salt as BufferSource } } } as AuthenticationExtensionsClientInputs,
  }
}

function prfOutput(cred: PublicKeyCredential): Uint8Array | null {
  const r = (cred.getClientExtensionResults() as any).prf?.results?.first
  return r ? new Uint8Array(r instanceof ArrayBuffer ? r : r.buffer) : null
}

/** The browser's answer to create(), as the server reads it. */
function attestationJSON(cred: PublicKeyCredential) {
  const r = cred.response as AuthenticatorAttestationResponse
  return {
    id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
    response: { clientDataJSON: b64u.enc(r.clientDataJSON), attestationObject: b64u.enc(r.attestationObject), transports: r.getTransports?.() || [] },
    extensions: {},
  }
}

/** The browser's answer to get(). */
export function assertionJSON(cred: PublicKeyCredential) {
  const r = cred.response as AuthenticatorAssertionResponse
  return {
    id: cred.id, rawId: b64u.enc(cred.rawId), type: cred.type,
    response: { clientDataJSON: b64u.enc(r.clientDataJSON), authenticatorData: b64u.enc(r.authenticatorData), signature: b64u.enc(r.signature), userHandle: r.userHandle ? b64u.enc(r.userHandle) : null },
    extensions: {},
  }
}

/** Friendly words for what the browser throws when a passkey prompt ends. */
export function passkeyError(e: unknown): Error {
  const n = (e as DOMException)?.name
  if (n === 'NotAllowedError' || n === 'AbortError') return new Error('The passkey prompt was closed or timed out.')
  if (n === 'InvalidStateError') return new Error('This passkey is already on your vault.')
  if (n === 'SecurityError') return new Error('Passkeys only work at the vault’s own address over HTTPS.')
  return e instanceof Error ? e : new Error(String(e))
}

/** The key from the passkey's secret (stretched like a master key). */
async function prfKey(out: Uint8Array): Promise<SymKey> { return stretch(out) }

/** The three wrapped keys a passkey unlocks with. */
async function keySet(user: SymKey, pk: SymKey) {
  const pair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' }, true, ['encrypt', 'decrypt'])
  const pub = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey))
  const priv = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pair.publicKey, user.raw as BufferSource))
  return { encryptedUserKey: '4.' + b64.enc(wrapped), encryptedPublicKey: await encryptBytes(pub, user), encryptedPrivateKey: await encryptBytes(priv, pk) }
}

/** Opens the user key with what a passkey sign-in returned. */
export async function userKeyFromPasskey(opt: { EncryptedPrivateKey: string; EncryptedUserKey: string }, out: Uint8Array): Promise<SymKey> {
  const priv = await decryptBytes(opt.EncryptedPrivateKey, await prfKey(out))
  const key = await crypto.subtle.importKey('pkcs8', priv as BufferSource, { name: 'RSA-OAEP', hash: 'SHA-1' }, false, ['decrypt'])
  const enc = opt.EncryptedUserKey
  if (!enc.startsWith('4.')) throw new Error('This passkey’s key is in a form this page can’t open.')
  return new SymKey(new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, key, b64.dec(enc.slice(2)) as BufferSource)))
}

type Call = <T = any>(method: string, path: string, body?: unknown) => Promise<T>

/**
 * Adds a passkey to the vault: create it (one prompt), get its secret (a
 * second prompt when the authenticator doesn't give it on creation), wrap
 * the user key with it and save. Returns whether it also unlocks.
 */
export async function addPasskey(call: Call, userKey: SymKey, masterPasswordHash: string, name: string): Promise<{ unlocks: boolean }> {
  const salt = await prfSalt()
  const start = await call<{ options: any; token: string }>('POST', '/webauthn/attestation-options', { masterPasswordHash })
  let cred: PublicKeyCredential
  try { cred = (await navigator.credentials.create({ publicKey: creationOptions(start.options, salt) })) as PublicKeyCredential }
  catch (e) { throw passkeyError(e) }
  if (!cred) throw new Error('No passkey was made.')
  const ext = cred.getClientExtensionResults() as any
  let out = prfOutput(cred)
  const supportsPrf = !!out || !!ext.prf?.enabled
  if (!out && supportsPrf) {
    try {
      const got = (await navigator.credentials.get({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)) as BufferSource, rpId: start.options.rp?.id, userVerification: 'required',
        allowCredentials: [{ id: cred.rawId, type: 'public-key' }], timeout: 300000,
        extensions: { prf: { eval: { first: salt as BufferSource } } } as AuthenticationExtensionsClientInputs,
      } })) as PublicKeyCredential
      out = got ? prfOutput(got) : null
    } catch { out = null /* saved as sign-in only; unlock can be turned on later */ }
  }
  const keys = out ? await keySet(userKey, await prfKey(out)) : {}
  await call('POST', '/webauthn', { deviceResponse: attestationJSON(cred), name, token: start.token, supportsPrf, ...keys })
  return { unlocks: !!out }
}

/** Turns on unlocking for a passkey that was saved without it. */
export async function enablePasskeyUnlock(call: Call, userKey: SymKey, masterPasswordHash: string) {
  const salt = await prfSalt()
  const start = await call<{ options: any; token: string }>('POST', '/webauthn/assertion-options', { masterPasswordHash })
  let cred: PublicKeyCredential
  try { cred = (await navigator.credentials.get({ publicKey: requestOptions(start.options, salt) })) as PublicKeyCredential }
  catch (e) { throw passkeyError(e) }
  const out = cred && prfOutput(cred)
  if (!out) throw new Error('This passkey (or this browser) can’t unlock a vault. It still signs you in.')
  await call('PUT', '/webauthn', { deviceResponse: assertionJSON(cred), token: start.token, ...(await keySet(userKey, await prfKey(out))) })
}

/** Asks for a passkey to sign in with. The answer goes to /identity. */
export async function passkeyAssertion(): Promise<{ token: string; response: ReturnType<typeof assertionJSON>; prf: Uint8Array | null }> {
  const salt = await prfSalt()
  const r = await fetch('/identity/accounts/webauthn/assertion-options')
  if (!r.ok) throw new Error('Signing in with a passkey isn’t available right now.')
  const start = await r.json()
  let cred: PublicKeyCredential
  try { cred = (await navigator.credentials.get({ publicKey: requestOptions(start.options, salt) })) as PublicKeyCredential }
  catch (e) { throw passkeyError(e) }
  if (!cred) throw new Error('No passkey was chosen.')
  return { token: start.token, response: assertionJSON(cred), prf: prfOutput(cred) }
}
