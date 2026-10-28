import { DurableObject } from "cloudflare:workers";

const CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
const genCode = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(6)), (n) => CHARS[n % CHARS.length]).join("");
const clean = (t) =>
  String(t || "")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .slice(0, 120);
const VID = /^[A-Za-z0-9_-]{11}$/;
const PIN = /^\d{4}$/;
const LOCK_MS = 15 * 60 * 1000;
const hex = (buf) => Array.from(new Uint8Array(buf), (x) => x.toString(16).padStart(2, "0")).join("");
const hashPin = async (pin, salt) =>
  hex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(salt + ":" + pin)));

export class Couple extends DurableObject {
  // Simple rate limiter (used with special "rl:<ip>" instances)
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
          hasPin: !!s.pinHash,
        },
      };
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
          me: me.name,
          msgs: (s.chat || []).filter((m) => m.id > since),
          otherSeen: other ? s.seen[other.name] || 0 : 0,
          otherName: other ? other.name : "",
          typing: !!(other && Date.now() - (this.typing[other.name] || 0) < 5000),
        },
      };
    }
    if (action === "media") {
      const m = await this.ctx.storage.get("m:" + Number(b.id));
      return m ? { status: 200, data: { media: m } } : { status: 404, data: { error: "Gone" } };
    }

    if (action === "musicGet") {
      return { status: 200, data: { now: Date.now(), music: s.music || null, playlist: s.playlist || [] } };
    }
    if (action === "musicSet") {
      const prev = s.music || {};
      const vid = b.vid ? String(b.vid) : prev.vid;
      if (!vid || !VID.test(vid)) {
        return { status: 400, data: { error: "Invalid YouTube link" } };
      }
      s.music = { vid, playing: !!b.playing, pos: Math.max(0, Number(b.pos) || 0), at: Date.now(), by: me.name };
      await save();
      return { status: 200, data: { ok: true } };
    }

    if (action === "search") {
      const q = String(b.q || "").trim().slice(0, 100);
      if (!q) return { status: 400, data: { error: "Type a song name" } };
      const key = this.env.YOUTUBE_KEY;
      if (!key) return { status: 500, data: { error: "Search is not set up yet" } };
      this.cache = this.cache || {};
      const ck = q.toLowerCase();
      const hit = this.cache[ck];
      if (hit && Date.now() - hit.t < 3600000) return { status: 200, data: { results: hit.r } };
      const day = new Date().toISOString().slice(0, 10);
      s.sq = s.sq && s.sq.day === day ? s.sq : { day, n: 0 };
      if (s.sq.n >= 25) {
        return { status: 429, data: { error: "Daily search limit reached. Use your playlist or paste a link." } };
      }
      s.sq.n++;
      await save();
      const u =
        "https://www.googleapis.com/youtube/v3/search?part=snippet&type=video&videoEmbeddable=true&maxResults=8&q=" +
        encodeURIComponent(q) +
        "&key=" +
        key;
      let r;
      try {
        r = await fetch(u);
      } catch (e) {
        return { status: 502, data: { error: "Search failed. Try again." } };
      }
      if (!r.ok) {
        return { status: 502, data: { error: r.status === 403 ? "Search quota is over for today" : "Search failed" } };
      }
      const j = await r.json();
      const results = (j.items || [])
        .filter((i) => i.id && i.id.videoId)
        .map((i) => ({ vid: i.id.videoId, title: clean(i.snippet.title), by: clean(i.snippet.channelTitle) }));
      this.cache[ck] = { t: Date.now(), r: results };
      return { status: 200, data: { results } };
    }

    if (action === "plAdd") {
      const vid = String(b.vid || "");
      if (!VID.test(vid)) return { status: 400, data: { error: "Invalid song" } };
      s.playlist = s.playlist || [];
      if (s.playlist.some((x) => x.vid === vid)) return { status: 200, data: { ok: true } };
      if (s.playlist.length >= 100) return { status: 400, data: { error: "Playlist is full (100 songs)" } };
      s.playlist.push({ vid, title: clean(b.title), by: clean(b.by), add: me.name });
      await save();
      return { status: 200, data: { ok: true } };
    }
    if (action === "plDel") {
      s.playlist = (s.playlist || []).filter((x) => x.vid !== b.vid);
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

    if (p[1] === "create") {
      const lim = limiter();
      const c = await lim.rlCheck("create", 5, 3600000);
      if (c.blocked) {
        return json({ error: "Too many new spaces from this network. Try again in " + c.retry + " min." }, 429);
      }
      for (let i = 0; i < 5; i++) {
        const code = genCode();
        const r = await env.COUPLE.get(env.COUPLE.idFromName(code)).act("create", body);
        if (r.status === 200) await lim.rlHit("create", 3600000);
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
    return json(r.data, r.status);
  },
};
