import { DurableObject } from "cloudflare:workers";

const CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
const genCode = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(6)), (n) => CHARS[n % CHARS.length]).join("");

export class Couple extends DurableObject {
  async act(action, b) {
    let s = (await this.ctx.storage.get("s")) || { created: false, members: [], start: null, mems: [] };
    const save = () => this.ctx.storage.put("s", s);
    const name = String(b.name || "").trim().slice(0, 30);
    const me = s.members.find((m) => m.token === b.token);

    if (action === "create") {
      if (s.created) return { status: 409, data: { error: "exists" } };
      if (!name) return { status: 400, data: { error: "Enter your name" } };
      const token = crypto.randomUUID();
      s.created = true;
      s.members.push({ name, token });
      await save();
      return { status: 200, data: { token, name } };
    }

    if (!s.created) return { status: 404, data: { error: "Code not found" } };

    if (action === "join") {
      if (!name) return { status: 400, data: { error: "Enter your name" } };
      const same = s.members.find((m) => m.name.toLowerCase() === name.toLowerCase());
      if (same) return { status: 200, data: { token: same.token, name: same.name } };
      if (s.members.length >= 2) return { status: 403, data: { error: "This couple already has two people" } };
      const token = crypto.randomUUID();
      s.members.push({ name, token });
      await save();
      return { status: 200, data: { token, name } };
    }

    if (!me) return { status: 401, data: { error: "Not signed in" } };

    if (action === "get") {
      return {
        status: 200,
        data: { now: Date.now(), start: s.start, mems: s.mems, names: s.members.map((m) => m.name) },
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
    return { status: 400, data: { error: "Unknown action" } };
  }
}

export default {
  async fetch(req, env) {
    const p = new URL(req.url).pathname.split("/").filter(Boolean);
    if (p[0] !== "api") return env.ASSETS.fetch(req);
    if (req.method !== "POST") return json({ error: "POST only" }, 405);
    const body = await req.json().catch(() => ({}));

    if (p[1] === "create") {
      for (let i = 0; i < 5; i++) {
        const code = genCode();
        const r = await env.COUPLE.get(env.COUPLE.idFromName(code)).act("create", body);
        if (r.status !== 409) return json({ ...r.data, code }, r.status);
      }
      return json({ error: "Try again" }, 500);
    }

    const code = (p[1] || "").toUpperCase();
    if (!/^[A-Z2-9]{6}$/.test(code)) return json({ error: "Code must be 6 characters" }, 400);
    const r = await env.COUPLE.get(env.COUPLE.idFromName(code)).act(p[2], body);
    return json(r.data, r.status);
  },
};
