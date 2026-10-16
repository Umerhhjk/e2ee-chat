(() => {
  const authForm = document.getElementById("auth-form");
  const tabLogin = document.getElementById("tab-login");
  const tabRegister = document.getElementById("tab-register");
  const authError = document.getElementById("auth-error");
  const gate = document.getElementById("gate");
  const app = document.getElementById("app");
  const meName = document.getElementById("me-name");
  const convos = document.getElementById("convos");
  const findForm = document.getElementById("find-form");
  const emptyThread = document.getElementById("empty-thread");
  const chat = document.getElementById("chat");
  const peerName = document.getElementById("peer-name");
  const log = document.getElementById("log");
  const composer = document.getElementById("composer");
  const draft = document.getElementById("draft");

  let mode = "login";
  let token = null;
  let me = null;
  let identity = null;
  let password = null;
  let activePeer = null;
  let pubCache = {};
  let socket = null;

  tabLogin.onclick = () => {
    mode = "login";
    tabLogin.classList.add("active");
    tabRegister.classList.remove("active");
    document.getElementById("auth-submit").textContent = "Enter";
  };
  tabRegister.onclick = () => {
    mode = "register";
    tabRegister.classList.add("active");
    tabLogin.classList.remove("active");
    document.getElementById("auth-submit").textContent = "Create sealed account";
  };

  function showError(msg) {
    authError.hidden = !msg;
    authError.textContent = msg || "";
  }

  async function api(path, options = {}) {
    const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
    if (token) headers.Authorization = "Bearer " + token;
    const res = await fetch(path, { ...options, headers });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = data.detail;
      const text = Array.isArray(detail)
        ? detail.map((d) => d.msg || JSON.stringify(d)).join(" ")
        : detail || "Request failed";
      throw new Error(text);
    }
    return data;
  }

  authForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    showError("");
    const username = document.getElementById("username").value.trim();
    const pw = document.getElementById("password").value;
    password = pw;
    try {
      if (mode === "register") {
        const generated = await CryptoKit.generateIdentity();
        const exported = await CryptoKit.exportBundle(generated);
        const wrapped = await CryptoKit.wrapPrivateKeys(pw, exported.private);
        const data = await api("/api/register", {
          method: "POST",
          body: JSON.stringify({
            username,
            password: pw,
            ecdh_public: exported.ecdh_public,
            ecdsa_public: exported.ecdsa_public,
            wrapped_keys: wrapped.wrapped_keys,
            wrap_salt: wrapped.wrap_salt,
          }),
        });
        await afterAuth(data, pw);
      } else {
        const data = await api("/api/login", {
          method: "POST",
          body: JSON.stringify({ username, password: pw }),
        });
        await afterAuth(data, pw);
      }
    } catch (err) {
      showError(err.message);
    }
  });

  async function afterAuth(data, pw) {
    token = data.token;
    me = data.user;
    const priv = await CryptoKit.unwrapPrivateKeys(pw, me.wrap_salt, me.wrapped_keys);
    identity = await CryptoKit.importIdentity({
      ecdh_public: me.ecdh_public,
      ecdsa_public: me.ecdsa_public,
      private: priv,
    });
    await LocalVault.open(pw, me.username);
    meName.textContent = me.username;
    gate.hidden = true;
    app.hidden = false;
    renderConvos();
    connectWs();
    await drainPending();
  }

  function connectWs() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    socket = new WebSocket(`${proto}://${location.host}/ws`);
    socket.onopen = () => socket.send(JSON.stringify({ type: "auth", token }));
    socket.onmessage = async (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.type === "message") await ingest(msg.message);
    };
    socket.onclose = () => {
      setTimeout(() => {
        if (token) connectWs();
      }, 1500);
    };
  }

  async function peerPublic(username) {
    if (pubCache[username]) return pubCache[username];
    const row = await api("/api/users/" + encodeURIComponent(username));
    pubCache[username] = await CryptoKit.importPublic(row.ecdh_public, row.ecdsa_public);
    return pubCache[username];
  }

  async function ingest(envelope) {
    if (LocalVault.alreadySeen(envelope.id)) return;
    try {
      const their = await peerPublic(envelope.sender);
      const text = await CryptoKit.openMessage({ identity, theirPub: their, me: me.username, envelope });
      await LocalVault.addMessage({
        id: envelope.id,
        peer: envelope.sender,
        direction: "in",
        body: text,
        ts: envelope.client_ts,
        seq: envelope.seq,
      });
      await api("/api/messages/ack", { method: "POST", body: JSON.stringify({ ids: [envelope.id] }) });
    } catch (err) {
      await LocalVault.markSeen(envelope.id);
      await LocalVault.addMessage({
        id: envelope.id,
        peer: envelope.sender,
        direction: "in",
        body: "[blocked: " + err.message + "]",
        ts: envelope.client_ts,
        seq: envelope.seq,
      });
    }
    renderConvos();
    if (activePeer === envelope.sender) renderThread();
  }

  async function drainPending() {
    const data = await api("/api/messages/pending");
    for (const envelope of data.messages) await ingest(envelope);
  }

  function renderConvos() {
    const rows = LocalVault.listConversations();
    convos.innerHTML = "";
    for (const row of rows) {
      const li = document.createElement("li");
      if (row.peer === activePeer) li.classList.add("active");
      li.innerHTML = `<strong>${escapeHtml(row.peer)}</strong><small>${escapeHtml(row.body)}</small>`;
      li.onclick = () => openThread(row.peer);
      convos.appendChild(li);
    }
  }

  function openThread(peer) {
    activePeer = peer;
    emptyThread.hidden = true;
    chat.hidden = false;
    peerName.textContent = peer;
    renderConvos();
    renderThread();
    draft.focus();
  }

  function renderThread() {
    log.innerHTML = "";
    for (const row of LocalVault.thread(activePeer)) {
      const li = document.createElement("li");
      li.className = row.direction === "out" ? "mine" : "theirs";
      if (row.body.startsWith("[blocked:")) li.className = "warn";
      const when = new Date(row.ts * 1000);
      li.innerHTML = `${escapeHtml(row.body)}<time>${when.toLocaleString()}</time>`;
      log.appendChild(li);
    }
    log.scrollTop = log.scrollHeight;
  }

  findForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("find-user").value.trim();
    if (!username || username === me.username) return;
    try {
      await peerPublic(username);
      document.getElementById("find-user").value = "";
      openThread(username);
    } catch (err) {
      alert(err.message);
    }
  });

  composer.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = draft.value.trim();
    if (!text || !activePeer) return;
    const seq = LocalVault.nextSeq(activePeer);
    const their = await peerPublic(activePeer);
    const envelope = await CryptoKit.sealMessage({
      identity,
      theirPub: their,
      me: me.username,
      peer: activePeer,
      text,
      seq,
    });
    await api("/api/messages", { method: "POST", body: JSON.stringify(envelope) });
    await LocalVault.addMessage({
      id: envelope.id,
      peer: activePeer,
      direction: "out",
      body: text,
      ts: envelope.client_ts,
      seq,
    });
    draft.value = "";
    renderConvos();
    renderThread();
  });

  draft.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      composer.requestSubmit();
    }
  });

  document.getElementById("logout").onclick = async () => {
    try {
      await api("/api/logout", { method: "POST" });
    } catch (_) {}
    await LocalVault.destroy();
    token = null;
    identity = null;
    password = null;
    me = null;
    if (socket) socket.close();
    location.reload();
  };

  function escapeHtml(value) {
    return value.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
  }
})();
