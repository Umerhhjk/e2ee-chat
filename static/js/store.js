const LocalVault = (() => {
  const DB_NAME = "sealed-chat";
  const STORE = "vault";
  let KEY = "sqlite";

  let sqlMod = null;
  let db = null;
  let password = null;

  function idb() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function idbGet() {
    const database = await idb();
    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE, "readonly");
      const req = tx.objectStore(STORE).get(KEY);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  }

  async function idbPut(value) {
    const database = await idb();
    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(value, KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  async function idbDel() {
    const database = await idb();
    return new Promise((resolve, reject) => {
      const tx = database.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete(KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }

  function schema(database) {
    database.run(`
      CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        peer TEXT NOT NULL,
        direction TEXT NOT NULL,
        body TEXT NOT NULL,
        ts INTEGER NOT NULL,
        seq INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS seen (id TEXT PRIMARY KEY);
      CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
      CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer, ts);
    `);
  }

  async function persist() {
    if (!db || !password) return;
    const exported = db.export();
    const sealed = await CryptoKit.encryptBytes(password, exported);
    await idbPut(sealed);
  }

  async function open(pw, username) {
    password = pw;
    KEY = "sqlite:" + (username || "default");
    if (!sqlMod) {
      sqlMod = await initSqlJs({
        locateFile: (file) => `https://cdnjs.cloudflare.com/ajax/libs/sql.js/1.10.3/${file}`,
      });
    }
    const blob = await idbGet();
    if (blob) {
      const bytes = await CryptoKit.decryptBytes(pw, new Uint8Array(blob));
      db = new sqlMod.Database(bytes);
    } else {
      db = new sqlMod.Database();
    }
    schema(db);
    await persist();
  }

  function alreadySeen(id) {
    const stmt = db.prepare("SELECT 1 FROM seen WHERE id = ?");
    stmt.bind([id]);
    const hit = stmt.step();
    stmt.free();
    return hit;
  }

  async function markSeen(id) {
    db.run("INSERT OR IGNORE INTO seen (id) VALUES (?)", [id]);
    await persist();
  }

  function nextSeq(peer) {
    const stmt = db.prepare("SELECT v FROM meta WHERE k = ?");
    stmt.bind(["seq:" + peer]);
    let n = 0;
    if (stmt.step()) n = Number(stmt.get()[0] || 0);
    stmt.free();
    n += 1;
    db.run("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", ["seq:" + peer, String(n)]);
    return n;
  }

  async function addMessage(row) {
    db.run(
      "INSERT OR REPLACE INTO messages (id, peer, direction, body, ts, seq) VALUES (?, ?, ?, ?, ?, ?)",
      [row.id, row.peer, row.direction, row.body, row.ts, row.seq]
    );
    db.run("INSERT OR IGNORE INTO seen (id) VALUES (?)", [row.id]);
    await persist();
  }

  function listConversations() {
    const stmt = db.prepare(`
      SELECT m.peer, m.body, m.ts
      FROM messages m
      JOIN (SELECT peer, MAX(ts) AS max_ts FROM messages GROUP BY peer) t
        ON m.peer = t.peer AND m.ts = t.max_ts
      ORDER BY m.ts DESC
    `);
    const rows = [];
    while (stmt.step()) {
      const [peer, body, ts] = stmt.get();
      rows.push({ peer, body, ts });
    }
    stmt.free();
    return rows;
  }

  function thread(peer) {
    const stmt = db.prepare("SELECT id, peer, direction, body, ts, seq FROM messages WHERE peer = ? ORDER BY ts, seq");
    stmt.bind([peer]);
    const rows = [];
    while (stmt.step()) {
      const [id, p, direction, body, ts, seq] = stmt.get();
      rows.push({ id, peer: p, direction, body, ts, seq });
    }
    stmt.free();
    return rows;
  }

  async function destroy() {
    const existing = await idbGet();
    if (existing) {
      const n = existing.byteLength || existing.length || 32;
      await idbPut(crypto.getRandomValues(new Uint8Array(n)));
      await idbPut(crypto.getRandomValues(new Uint8Array(n)));
    }
    await idbDel();
    if (db) db.close();
    db = null;
    password = null;
  }

  return { open, alreadySeen, markSeen, nextSeq, addMessage, listConversations, thread, destroy, persist };
})();
