const CryptoKit = (() => {
  const te = new TextEncoder();
  const td = new TextDecoder();

  function b64(bytes) {
    let s = "";
    bytes = new Uint8Array(bytes);
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  }

  function unb64(text) {
    const bin = atob(text);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToJwk(jwk) {
    return JSON.stringify(jwk);
  }

  async function generateIdentity() {
    const ecdh = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const ecdsa = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    return { ecdh, ecdsa };
  }

  async function exportBundle(identity) {
    const ecdhPub = await crypto.subtle.exportKey("jwk", identity.ecdh.publicKey);
    const ecdhPriv = await crypto.subtle.exportKey("jwk", identity.ecdh.privateKey);
    const ecdsaPub = await crypto.subtle.exportKey("jwk", identity.ecdsa.publicKey);
    const ecdsaPriv = await crypto.subtle.exportKey("jwk", identity.ecdsa.privateKey);
    return {
      ecdh_public: bytesToJwk(ecdhPub),
      ecdsa_public: bytesToJwk(ecdsaPub),
      private: { ecdh: ecdhPriv, ecdsa: ecdsaPriv },
    };
  }

  async function importIdentity(bundle) {
    const ecdh = {
      publicKey: await crypto.subtle.importKey(
        "jwk",
        JSON.parse(bundle.ecdh_public),
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      ),
      privateKey: await crypto.subtle.importKey(
        "jwk",
        bundle.private.ecdh,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveBits"]
      ),
    };
    const ecdsa = {
      publicKey: await crypto.subtle.importKey(
        "jwk",
        JSON.parse(bundle.ecdsa_public),
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        []
      ),
      privateKey: await crypto.subtle.importKey(
        "jwk",
        bundle.private.ecdsa,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign"]
      ),
    };
    return { ecdh, ecdsa };
  }

  async function importPublic(ecdhJson, ecdsaJson) {
    return {
      ecdh: await crypto.subtle.importKey(
        "jwk",
        JSON.parse(ecdhJson),
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      ),
      ecdsa: await crypto.subtle.importKey(
        "jwk",
        JSON.parse(ecdsaJson),
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"]
      ),
    };
  }

  async function deriveWrapKey(password, saltBytes) {
    const base = await crypto.subtle.importKey("raw", te.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: saltBytes, iterations: 310000, hash: "SHA-256" },
      base,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function wrapPrivateKeys(password, privateBundle) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveWrapKey(password, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const pt = te.encode(JSON.stringify(privateBundle));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt);
    return {
      wrap_salt: b64(salt),
      wrapped_keys: b64(iv) + "." + b64(ct),
    };
  }

  async function unwrapPrivateKeys(password, wrapSalt, wrappedKeys) {
    const salt = unb64(wrapSalt);
    const [ivB64, ctB64] = wrappedKeys.split(".");
    const key = await deriveWrapKey(password, salt);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(ivB64) }, key, unb64(ctB64));
    return JSON.parse(td.decode(pt));
  }

  async function conversationKey(myEcdhPrivate, theirEcdhPublic, me, peer) {
    const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: theirEcdhPublic }, myEcdhPrivate, 256);
    const shared = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
    const pair = [me, peer].sort().join(":");
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: te.encode("sealed-chat-v1"), info: te.encode(pair) },
      shared,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  function aad(fields) {
    return te.encode([fields.id, fields.sender, fields.recipient, String(fields.seq), String(fields.client_ts)].join("|"));
  }

  async function sealMessage({ identity, theirPub, me, peer, text, seq }) {
    const id = crypto.randomUUID();
    const client_ts = Math.floor(Date.now() / 1000);
    const key = await conversationKey(identity.ecdh.privateKey, theirPub.ecdh, me, peer);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const payload = te.encode(JSON.stringify({ v: 1, text }));
    const fields = { id, sender: me, recipient: peer, seq, client_ts };
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(fields) }, key, payload);
    const toSign = te.encode(`${id}|${me}|${peer}|${seq}|${client_ts}|${b64(iv)}|${b64(ciphertext)}`);
    const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, identity.ecdsa.privateKey, toSign);
    return {
      id,
      recipient: peer,
      iv: b64(iv),
      ciphertext: b64(ciphertext),
      signature: b64(signature),
      seq,
      client_ts,
    };
  }

  async function openMessage({ identity, theirPub, me, envelope }) {
    const signed = te.encode(
      `${envelope.id}|${envelope.sender}|${envelope.recipient}|${envelope.seq}|${envelope.client_ts}|${envelope.iv}|${envelope.ciphertext}`
    );
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      theirPub.ecdsa,
      unb64(envelope.signature),
      signed
    );
    if (!ok) throw new Error("Signature check failed. Message may have been tampered with.");
    const key = await conversationKey(identity.ecdh.privateKey, theirPub.ecdh, me, envelope.sender);
    const fields = {
      id: envelope.id,
      sender: envelope.sender,
      recipient: envelope.recipient,
      seq: envelope.seq,
      client_ts: envelope.client_ts,
    };
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64(envelope.iv), additionalData: aad(fields) },
      key,
      unb64(envelope.ciphertext)
    );
    const obj = JSON.parse(td.decode(pt));
    if (typeof obj.text !== "string") throw new Error("Malformed plaintext.");
    return obj.text;
  }

  async function encryptBytes(password, bytes) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveWrapKey(password, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
    const out = new Uint8Array(16 + 12 + ct.byteLength);
    out.set(salt, 0);
    out.set(iv, 16);
    out.set(new Uint8Array(ct), 28);
    return out;
  }

  async function decryptBytes(password, blob) {
    const salt = blob.slice(0, 16);
    const iv = blob.slice(16, 28);
    const ct = blob.slice(28);
    const key = await deriveWrapKey(password, salt);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    return new Uint8Array(pt);
  }

  return {
    b64,
    unb64,
    generateIdentity,
    exportBundle,
    importIdentity,
    importPublic,
    wrapPrivateKeys,
    unwrapPrivateKeys,
    sealMessage,
    openMessage,
    encryptBytes,
    decryptBytes,
  };
})();
