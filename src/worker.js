import { DurableObject } from "cloudflare:workers";

const CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
const genCode = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(6)), (n) => CHARS[n % CHARS.length]).join("");
const PIN = /^\d{4}$/;
const LOCK_MS = 15 * 60 * 1000;
const MAX_TRACKS = 10;
const MAX_BYTES = 10 * 1024 * 1024;
const CHUNK = 700 * 1024;
const hex = (buf) => Array.from(new Uint8Array(buf), (x) => x.toString(16).padStart(2, "0")).join("");
const hashPin = async (pin, salt) =>
  hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(salt + ":" + pin)));

const COOKIE = "tg";
const YEAR = 31536000;
const setCookie = (v, age) => `${COOKIE}=${v}; Path=/; Max-Age=${age}; HttpOnly; Secure; SameSite=Lax`;
const withCookie = (res, c) => {
  res.headers.append("Set-Cookie", c);
  return res;
};
const readCookie = (req) => {
  const m = (req.headers.get("Cookie") || "")
    .split(";")
    .map((x) => x.trim())
    .find((x) => x.startsWith(COOKIE + "="));
  return m ? m.slice(COOKIE.length + 1) : "";
};

export class Couple extends DurableObject {
  async rlCheck(kind, max, win) {
    const d = (await this.ctx.storage.get(kind)) || { n: 0, t: 0 };
    if (Date.now() - d.t > win) return { blocked: false };
    return { blocked: d.n >= max, retry: Math.max(1, Math.ceil((d.t + win - Date.now()) / 60000)) };
  }
  async rlHit(kind, win) {
    let d = (await this.ctx.storage.get(kind)) || { n: 0, t: 0 };
    if (Date.now() - d.t > win) d = { n: 0, t: Date.now() };
    d.n++;
    await this.ctx.storage.put(kind, d);
  }
  async dropChunks(t) {
    for (let i = 0; i < t.n; i++) await this.ctx.storage.delete("a:" + t.id + ":" + i);
  }

  async act(action, b) {
    let s = (await this.ctx.storage.get("s")) || { created: false, members: [], start: null, mems: [] };
    const save = () => this.ctx.storage.put("s", s);
    const name = String(b.name || "").trim().slice(0, 30);
    const me = s.members.find((m) => m.token === b.token);

    if (action === "create") {
      if (s.created) return { status: 409, data: { error: "exists" } };
      if (!name) return { status: 400, data: { error: "Enter your name" } };
      const pin = String(b.pin || "");
      if (!PIN.test(pin)) return { status: 400, data: { error: "Choose a 4-digit PIN" } };
      const token = crypto.randomUUID();
      s.created = true;
      s.salt = crypto.randomUUID();
      s.pinHash = await hashPin(pin, s.salt);
      s.members.push({ name, token });
      await save();
      return { status: 200, data: { token, name } };
    }

    if (!s.created) return { status: 404, data: { error: "Code not found" } };

    if (action === "join") {
      if (!name) return { status: 400, data: { error: "Enter your name" } };
      if (s.fails && s.fails.n >= 5 && Date.now() - s.fails.t < LOCK_MS) {
        const m = Math.ceil((s.fails.t + LOCK_MS - Date.now()) / 60000);
        return { status: 429, data: { error: "Too many wrong tries. Try again in " + m + " min." } };
      }
      if (s.pinHash) {
        const pin = String(b.pin || "");
        const ok = PIN.test(pin) && (await hashPin(pin, s.salt)) === s.pinHash;
        if (!ok) {
          s.fails =
            s.fails && Date.now() - s.fails.t < LOCK_MS ? { n: s.fails.n + 1, t: s.fails.t } : { n: 1, t: Date.now() };
          await save();
          return { status: 403, data: { error: "Wrong PIN" } };
        }
      }
      if (s.fails) {
        s.fails = null;
        await save();
      }
      const same = s.members.find((m) => m.name.toLowerCase() === name.toLowerCase());
      if (same) return { status: 200, data: { token: same.token, name: same.name } };
      if (s.members.length >= 2) return { status: 403, data: { error: "This couple already has two people" } };
      const token = crypto.randomUUID();
      s.members.push({ name, token });
      await save();
      return { status: 200, data: { token, name } };
    }

    if (!me) return { status: 401, data: { error: "Not signed in" } };

    if (action === "setPin") {
      if (s.pinHash) return { status: 400, data: { error: "PIN is already set" } };
      const pin = String(b.pin || "");
      if (!PIN.test(pin)) return { status: 400, data: { error: "Choose a 4-digit PIN" } };
      s.salt = crypto.randomUUID();
      s.pinHash = await hashPin(pin, s.salt);
      await save();
      return { status: 200, data: { ok: true } };
    }

    if (action === "get") {
      return {
        status: 200,
        data: {
          now: Date.now(),
          start: s.start,
          mems: s.mems,
          names: s.members.map((m) => m.name),
          me: me.name,
          hasPin: !!s.pinHash,
          pics: s.picv || {},
        },
      };
    }

    if (action === "setPic") {
      const img = String(b.img || "");
      s.picv = s.picv || {};
      const k = "pic:" + me.name.toLowerCase();
      if (!img) {
        await this.ctx.storage.delete(k);
        delete s.picv[me.name];
        await save();
        return { status: 200, data: { ok: true } };
      }
      if (!/^data:image\/(jpeg|png|webp);base64,/.test(img) || img.length > 400000) {
        return { status: 400, data: { error: "Photo is too big" } };
      }
      await this.ctx.storage.put(k, img);
      s.picv[me.name] = Date.now();
      await save();
      return { status: 200, data: { ok: true } };
    }
    if (action === "getPic") {
      const who = s.members.find((m) => m.name === b.name);
      const img = who ? await this.ctx.storage.get("pic:" + who.name.toLowerCase()) : null;
      return img ? { status: 200, data: { img } } : { status: 404, data: { error: "No photo" } };
    }

    if (action === "setStart") {
      const t = Number(b.start);
      if (!Number.isFinite(t)) return { status: 400, data: { error: "Bad date" } };
      s.start = t;
      await save();
      return { status: 200, data: { ok: true } };
    }
    if (action === "addMem") {
      const text = String(b.text || "").trim().slice(0, 500);
      if (!text) return { status: 400, data: { error: "Write something" } };
      const ts = Number.isFinite(Number(b.ts)) && b.ts ? Number(b.ts) : Date.now();
      s.mems.unshift({ id: crypto.randomUUID(), text, ts, by: me.name });
      s.mems.sort((a, c) => c.ts - a.ts);
      s.mems = s.mems.slice(0, 500);
      await save();
      return { status: 200, data: { ok: true } };
    }
    if (action === "delMem") {
      s.mems = s.mems.filter((m) => m.id !== b.id);
      await save();
      return { status: 200, data: { ok: true } };
    }

    if (action === "send") {
      const kind = ["text", "image", "voice"].includes(b.kind) ? b.kind : "text";
      const text = String(b.text || "").trim().slice(0, 1000);
      let media = null;
      if (kind === "text") {
        if (!text) return { status: 400, data: { error: "Write something" } };
      } else {
        media = String(b.media || "");
        if (!media.startsWith("data:") || media.length > 1800000) {
          return { status: 400, data: { error: "File is too big" } };
        }
      }
      s.chat = s.chat || [];
      s.nextId = (s.nextId || 0) + 1;
      const id = s.nextId;
      s.chat.push({ id, kind, text, by: me.name, ts: Date.now(), dur: Number(b.dur) || 0 });
      if (media) await this.ctx.storage.put("m:" + id, media);
      while (s.chat.length > 300) {
        const old = s.chat.shift();
        if (old.kind !== "text") await this.ctx.storage.delete("m:" + old.id);
      }
      if (this.typing) delete this.typing[me.name];
      await save();
      return { status: 200, data: { ok: true, id } };
    }

    // Chat + room state in one call (messages, seen/typing, shared music state, song list, call presence)
    if (action === "chat") {
      const since = Number(b.since) || 0;
      const mySeen = Number(b.seen) || 0;
      s.seen = s.seen || {};
      if (mySeen > (s.seen[me.name] || 0)) {
        s.seen[me.name] = mySeen;
        await save();
      }
      this.typing = this.typing || {};
      if (b.typing) this.typing[me.name] = Date.now();
      const other = s.members.find((m) => m.name !== me.name);
      return {
        status: 200,
        data: {
          now: Date.now(),
          me: me.name,
          names: s.members.map((m) => m.name),
          pics: s.picv || {},
          msgs: (s.chat || []).filter((m) => m.id > since),
          otherSeen: other ? s.seen[other.name] || 0 : 0,
          otherName: other ? other.name : "",
          typing: !!(other && Date.now() - (this.typing[other.name] || 0) < 5000),
          callOn: !!(other && this.sig && Date.now() - (this.sig.on[other.name] || 0) < 6000),
          music: s.music || null,
          lib: (s.lib || [])
            .filter((t) => t.ready)
            .map((t) => ({ id: t.id, name: t.name, size: t.size, mime: t.mime, n: t.n, by: t.by })),
        },
      };
    }
    if (action === "media") {
      const m = await this.ctx.storage.get("m:" + Number(b.id));
      return m ? { status: 200, data: { media: m } } : { status: 404, data: { error: "Gone" } };
    }

    // ---- Voice call signaling (short-lived, kept in memory) ----
    if (action === "rtcGet") {
      const now = Date.now();
      this.sig = this.sig || { seq: 0, q: [], on: {} };
      if (b.in) this.sig.on[me.name] = now;
      else delete this.sig.on[me.name];
      this.sig.q = this.sig.q.filter((m) => now - m.t < 60000);
      const other = s.members.find((m) => m.name !== me.name);
      const since = Number(b.since) || 0;
      return {
        status: 200,
        data: {
          seq: this.sig.seq,
          msgs: b.fresh ? [] : this.sig.q.filter((m) => m.to === me.name && m.id > since),
          other: !!(other && now - (this.sig.on[other.name] || 0) < 6000),
          otherName: other ? other.name : "",
        },
      };
    }
    if (action === "rtcSend") {
      const other = s.members.find((m) => m.name !== me.name);
      if (!other) return { status: 400, data: { error: "Partner has not joined yet" } };
      if (!b.m || JSON.stringify(b.m).length > 12000) return { status: 400, data: { error: "Bad signal" } };
      this.sig = this.sig || { seq: 0, q: [], on: {} };
      this.sig.seq++;
      this.sig.q.push({ id: this.sig.seq, to: other.name, t: Date.now(), m: b.m });
      if (this.sig.q.length > 200) this.sig.q.shift();
      return { status: 200, data: { ok: true } };
    }

    // ---- Songs: private library for this couple, stored in chunks ----
    if (action === "libInit") {
      const size = Number(b.size);
      if (!Number.isFinite(size) || size <= 0) return { status: 400, data: { error: "Bad file" } };
      if (size > MAX_BYTES) return { status: 400, data: { error: "Song is too big (max 10 MB)" } };
      s.lib = s.lib || [];
      const keep = [];
      for (const t of s.lib) {
        if (t.ready || Date.now() - t.ts < 3600000) keep.push(t);
        else await this.dropChunks(t);
      }
      s.lib = keep;
      if (s.lib.length >= MAX_TRACKS) {
        return { status: 400, data: { error: "Library is full (10 songs). Remove one first." } };
      }
      const mime = /^audio\//.test(String(b.mime || "")) ? String(b.mime).slice(0, 40) : "audio/mpeg";
      const id = crypto.randomUUID().slice(0, 8);
      s.lib.push({
        id,
        name: String(b.name || "Song").replace(/[<>]/g, "").slice(0, 80),
        size,
        mime,
        n: Math.ceil(size / CHUNK),
        have: [],
        ready: false,
        by: me.name,
        ts: Date.now(),
      });
      await save();
      return { status: 200, data: { id, chunk: CHUNK } };
    }
    if (action === "libPut") {
      const t = (s.lib || []).find((x) => x.id === b.id && !x.ready && x.by === me.name);
      const i = Number(b.i);
      const d = String(b.d || "");
      if (!t || !Number.isInteger(i) || i < 0 || i >= t.n) return { status: 400, data: { error: "Bad part" } };
      if (d.length > 940000 || !/^[A-Za-z0-9+/=]+$/.test(d)) return { status: 400, data: { error: "Bad data" } };
      await this.ctx.storage.put("a:" + t.id + ":" + i, d);
      if (!t.have.includes(i)) t.have.push(i);
      if (t.have.length === t.n) {
        t.ready = true;
        t.have = [];
      }
      await save();
      return { status: 200, data: { ok: true, ready: t.ready } };
    }
    if (action === "libGet") {
      const t = (s.lib || []).find((x) => x.id === b.id && x.ready);
      const i = Number(b.i);
      if (!t || !Number.isInteger(i) || i < 0 || i >= t.n) return { status: 404, data: { error: "Gone" } };
      const d = await this.ctx.storage.get("a:" + t.id + ":" + i);
      return d ? { status: 200, data: { d } } : { status: 404, data: { error: "Gone" } };
    }
    if (action === "libDel") {
      const t = (s.lib || []).find((x) => x.id === b.id);
      if (!t) return { status: 200, data: { ok: true } };
      await this.dropChunks(t);
      s.lib = s.lib.filter((x) => x.id !== b.id);
      if (s.music && s.music.id === b.id) s.music = null;
      await save();
      return { status: 200, data: { ok: true } };
    }
    if (action === "playSet") {
      const t = (s.lib || []).find((x) => x.id === b.id && x.ready);
      if (!t) return { status: 400, data: { error: "Song not found" } };
      const now = Date.now();
      let at = Number(b.at);
      if (!Number.isFinite(at) || Math.abs(at - now) > 5000) at = now;
      s.music = { id: t.id, playing: !!b.playing, pos: Math.max(0, Number(b.pos) || 0), at, by: me.name };
      await save();
      return { status: 200, data: { ok: true } };
    }

    return { status: 400, data: { error: "Unknown action" } };
  }
}

export default {
  async fetch(req, env) {
    const p = new URL(req.url).pathname.split("/").filter(Boolean);
    if (p[0] !== "api") return env.ASSETS.fetch(req);
    if (req.method !== "POST") return json({ error: "POST only" }, 405);
    const body = await req.json().catch(() => ({}));
    const ip = req.headers.get("CF-Connecting-IP") || "unknown";
    const limiter = () => env.COUPLE.get(env.COUPLE.idFromName("rl:" + ip));

    if (p[1] === "logout") return withCookie(json({ ok: true }), setCookie("", 0));

    if (p[1] === "resume") {
      let code = "";
      let token = "";
      if (body.code && body.token) {
        code = String(body.code).toUpperCase();
        token = String(body.token);
      } else {
        [code, token] = readCookie(req).split(".");
      }
      if (!/^[A-Z2-9]{6}$/.test(code || "") || !token) return json({ error: "No session" }, 401);
      const r = await env.COUPLE.get(env.COUPLE.idFromName(code)).act("get", { token });
      if (r.status !== 200) return withCookie(json({ error: "No session" }, 401), setCookie("", 0));
      return withCookie(json({ code, token, name: r.data.me }), setCookie(code + "." + token, YEAR));
    }

    if (p[1] === "create") {
      const lim = limiter();
      const c = await lim.rlCheck("create", 5, 3600000);
      if (c.blocked) {
        return json({ error: "Too many new spaces from this network. Try again in " + c.retry + " min." }, 429);
      }
      for (let i = 0; i < 5; i++) {
        const code = genCode();
        const r = await env.COUPLE.get(env.COUPLE.idFromName(code)).act("create", body);
        if (r.status === 200) {
          await lim.rlHit("create", 3600000);
          return withCookie(json({ ...r.data, code }, 200), setCookie(code + "." + r.data.token, YEAR));
        }
        if (r.status !== 409) return json({ ...r.data, code }, r.status);
      }
      return json({ error: "Try again" }, 500);
    }

    const code = (p[1] || "").toUpperCase();
    if (!/^[A-Z2-9]{6}$/.test(code)) return json({ error: "Code must be 6 characters" }, 400);

    const isJoin = p[2] === "join";
    let lim = null;
    if (isJoin) {
      lim = limiter();
      const c = await lim.rlCheck("joinfail", 10, 900000);
      if (c.blocked) return json({ error: "Too many wrong tries. Try again in " + c.retry + " min." }, 429);
    }
    const r = await env.COUPLE.get(env.COUPLE.idFromName(code)).act(p[2], body);
    if (isJoin && (r.status === 403 || r.status === 404)) await lim.rlHit("joinfail", 900000);
    if (isJoin && r.status === 200) {
      return withCookie(json(r.data, 200), setCookie(code + "." + r.data.token, YEAR));
    }
    return json(r.data, r.status);
  },
};
