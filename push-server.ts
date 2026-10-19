// Deno Deploy push server using standard Web Push (no Firebase Messaging / FCM project settings needed).
// Subscriptions are stored in your Firestore (collection "pushSubs") through the service account you already have.
// Env vars: FB_ADMIN_PROJECT_ID, FB_ADMIN_CLIENT_EMAIL, FB_ADMIN_PRIVATE_KEY, NOTIFY_SECRET,
//           VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT, ALLOWED_ORIGIN (optional)
import webpush from "npm:web-push@3.6.7";

const SA = {
  project_id: Deno.env.get("FB_ADMIN_PROJECT_ID")!,
  client_email: Deno.env.get("FB_ADMIN_CLIENT_EMAIL")!,
  private_key: Deno.env.get("FB_ADMIN_PRIVATE_KEY")!.replace(/\\n/g, "\n").replace(/^"|"$/g, ""),
};
const SECRET = Deno.env.get("NOTIFY_SECRET") ?? "";
const SUPER_UID = Deno.env.get("SUPER_ADMIN_UID") ?? ""; // if set, only this UID can be super admin
const ORIGIN = Deno.env.get("ALLOWED_ORIGIN") ?? "*";
const GROQ_KEY = Deno.env.get("GROQ_API_KEY") ?? "";
const GROQ_MODEL = Deno.env.get("GROQ_MODEL") ?? "openai/gpt-oss-20b";
const VAPID_PUBLIC = Deno.env.get("VAPID_PUBLIC_KEY") ?? "";
const VAPID_PRIVATE = Deno.env.get("VAPID_PRIVATE_KEY") ?? "";
const VAPID_SUBJECT = Deno.env.get("VAPID_SUBJECT") ?? "https://goodforyoutest.netlify.app";
console.log(`[startup] project=${SA.project_id} key_loaded=${SA.private_key.includes("BEGIN PRIVATE KEY")} secret_set=${!!SECRET} vapid_set=${!!VAPID_PUBLIC && !!VAPID_PRIVATE}`);
try {
  webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC, VAPID_PRIVATE);
} catch (e) {
  console.error("[startup] VAPID keys invalid:", String(e));
}

const CORS = {
  "Access-Control-Allow-Origin": ORIGIN,
  "Access-Control-Allow-Headers": "content-type,x-secret,authorization",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
};
const json = (o: unknown, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { ...CORS, "content-type": "application/json" } });

// ---------- Google auth for Firestore (service account) ----------
const b64u = (d: ArrayBuffer | string) => {
  const u = typeof d === "string" ? new TextEncoder().encode(d) : new Uint8Array(d);
  return btoa(String.fromCharCode(...u)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
let cached = { token: "", exp: 0 };
async function accessToken(): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (cached.token && cached.exp > now + 60) return cached.token;
  const head = b64u(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64u(JSON.stringify({
    iss: SA.client_email,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  }));
  const der = Uint8Array.from(
    atob(SA.private_key.replace(/-----[^-]+-----/g, "").replace(/\s/g, "")),
    (c) => c.charCodeAt(0),
  );
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(`${head}.${claim}`));
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: `${head}.${claim}.${b64u(sig)}`,
    }),
  });
  const j = await res.json();
  if (!j.access_token) {
    console.error("[auth] FAILED to get Google access token:", res.status, JSON.stringify(j));
    throw new Error("auth failed: " + (j.error_description || j.error || res.status));
  }
  console.log("[auth] got Google access token OK");
  cached = { token: j.access_token, exp: now + 3500 };
  return cached.token;
}

// ---------- Firestore REST helpers ----------
const DB = `https://firestore.googleapis.com/v1/projects/${SA.project_id}/databases/(default)/documents`;
const COL = "pushSubs";
const fsHeaders = async () => ({ Authorization: `Bearer ${await accessToken()}`, "content-type": "application/json" });
const str = (v: string) => ({ stringValue: v });

async function sha256Hex(s: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function saveSub(sub: { endpoint: string; keys: { p256dh: string; auth: string } }, orgId: string, role: string, uid?: string) {
  const id = await sha256Hex(sub.endpoint);
  const res = await fetch(`${DB}/${COL}/${id}`, {
    method: "PATCH",
    headers: await fsHeaders(),
    body: JSON.stringify({
      fields: {
        endpoint: str(sub.endpoint),
        p256dh: str(sub.keys.p256dh),
        auth: str(sub.keys.auth),
        orgId: str(String(orgId).toUpperCase()),
        role: str(String(role || "").toLowerCase()),
        uid: str(String(uid || "")),
        updatedAt: { timestampValue: new Date().toISOString() },
      },
    }),
  });
  const text = await res.text();
  console.log(`[subscribe] saved doc=${id.slice(0, 10)}... org=${orgId} role=${role} http=${res.status} ${res.ok ? "OK" : "FAILED " + text}`);
  return res.ok;
}

type Sub = { id: string; endpoint: string; p256dh: string; auth: string; uid: string; orgId: string };

async function findSubs(orgId?: string, role?: string, uid?: string): Promise<Sub[]> {
  const filters: unknown[] = [];
  if (uid) filters.push({ fieldFilter: { field: { fieldPath: "uid" }, op: "EQUAL", value: str(String(uid)) } });
  else {
  if (orgId) filters.push({ fieldFilter: { field: { fieldPath: "orgId" }, op: "EQUAL", value: str(String(orgId).toUpperCase()) } });
  if (role) filters.push({ fieldFilter: { field: { fieldPath: "role" }, op: "EQUAL", value: str(String(role).toLowerCase()) } });
  }
  const q: Record<string, unknown> = { from: [{ collectionId: COL }] };
  if (filters.length === 1) q.where = filters[0];
  if (filters.length > 1) q.where = { compositeFilter: { op: "AND", filters } };
  const res = await fetch(`${DB}:runQuery`, { method: "POST", headers: await fsHeaders(), body: JSON.stringify({ structuredQuery: q }) });
  const rows = await res.json();
  if (!res.ok) {
    console.error("[query] Firestore query FAILED:", res.status, JSON.stringify(rows));
    throw new Error("firestore query failed: " + res.status);
  }
  return rows.filter((r: any) => r.document).map((r: any) => {
    const f = r.document.fields;
    return { id: r.document.name.split("/").pop(), endpoint: f.endpoint.stringValue, p256dh: f.p256dh.stringValue, auth: f.auth.stringValue, uid: f.uid?.stringValue ?? "", orgId: f.orgId?.stringValue ?? "" };
  });
}

async function deleteSub(id: string) {
  await fetch(`${DB}/${COL}/${id}`, { method: "DELETE", headers: await fsHeaders() }).catch(() => {});
}

// ---------- Sending ----------
type Item = { sub: Sub; payload: string };

async function sendItems(items: Item[]) {
  let sent = 0, failed = 0, removed = 0;
  for (let i = 0; i < items.length; i += 50) {
    await Promise.all(items.slice(i, i + 50).map(async ({ sub: s, payload }) => {
      try {
        await webpush.sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, payload, { TTL: 86400, urgency: "high" });
        sent++;
      } catch (e: any) {
        failed++;
        console.error(`[send] device ${s.id.slice(0, 10)}... failed status=${e?.statusCode} body=${e?.body ?? e?.message}`);
        if (e?.statusCode === 404 || e?.statusCode === 410) { removed++; await deleteSub(s.id); }
      }
    }));
  }
  console.log(`[send] done sent=${sent} failed=${failed} removed_expired=${removed}`);
  return { sent, failed, removed, matched: items.length };
}

async function send(target: { orgId?: string; role?: string; uid?: string }, title: string, body: string, url = "/") {
  const subs = await findSubs(target.orgId, target.role, target.uid);
  console.log(`[send] target=${JSON.stringify(target)} title="${title}" matching_devices=${subs.length}`);
  const payload = JSON.stringify({ title, body, url });
  return sendItems(subs.map((sub) => ({ sub, payload })));
}

// ---------- Server ----------
Deno.serve(async (req) => {
  const path = new URL(req.url).pathname;
  console.log(`[req] ${req.method} ${path} origin=${req.headers.get("origin") ?? "-"}`);
  if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
  if (req.method !== "POST") return json({ ok: true, hint: "server is running" });
  try {
    return await handle(req, path);
  } catch (e) {
    console.error(`[error] ${req.method} ${path} crashed:`, e instanceof Error ? e.stack ?? e.message : e);
    return json({ ok: false, error: String(e instanceof Error ? e.message : e) }, 500);
  }
});

async function handle(req: Request, path: string): Promise<Response> {
  const b = await req.json().catch((e) => { console.error("[req] bad JSON body:", String(e)); return {}; });
  console.log(`[req] body keys=${Object.keys(b).join(",")} orgId=${b.orgId ?? "-"} role=${b.role ?? "-"} uid=${b.uid ?? "-"}`);

  // A student's / teacher's device registers itself
  if (path === "/subscribe") {
    const s = b.subscription;
    if (!s?.endpoint || !s?.keys?.p256dh || !s?.keys?.auth || !b.orgId) return json({ error: "subscription and orgId required" }, 400);
    return json({ ok: await saveSub(s, b.orgId, b.role, b.uid) });
  }

  // Super admin only (checked with the caller's Firebase login token, no shared secret in the browser)
  if (path.startsWith("/admin/")) {
    if (!(await requireSuper(req))) return json({ error: "forbidden: super admin login required" }, 403);
    if (path === "/admin/preview") {
      if (!GROQ_KEY) return json({ error: "GROQ_API_KEY is not set on the notification server" }, 400);
      const instruction = String(b.instruction ?? "").trim().slice(0, 500);
      if (!instruction) return json({ error: "instruction required" }, 400);
      let info: PInfo = { name: "Aarav", batch: "", lastTest: "", lastPct: null, daysSince: null };
      let sampleFor = "a sample student named Aarav";
      const first = b.audience?.type === "users" ? (b.audience.uids ?? [])[0] : null;
      if (first) {
        const m = await userInfo([String(first)], true);
        if (m[String(first)]) { info = m[String(first)]; sampleFor = info.name || "this person"; }
      }
      try { return json({ ok: true, sampleFor, ...(await aiOne(instruction, info)) }); }
      catch (e) { return json({ error: "AI failed: " + String(e instanceof Error ? e.message : e) }, 502); }
    }
    if (path === "/admin/send") {
      const spec = cleanSpec(b);
      if (typeof spec === "string") return json({ error: spec }, 400);
      return json(await dispatch(spec));
    }
    if (path.startsWith("/admin/auth/")) return await authAdmin(req, path, b);
    return json({ error: "not found" }, 404);
  }

  // Admin / super admin sends: orgId and role are optional (none = everyone, one = that group, both = only matching)
  if (path === "/notify") {
    if (!SECRET || req.headers.get("x-secret") !== SECRET) {
      console.warn(`[notify] FORBIDDEN: secret ${SECRET ? "does not match" : "is not set in Deno env"}`);
      return json({ error: "forbidden" }, 403);
    }
    // dryRun: only count how many devices would receive it
    if (b.dryRun) {
      const n = (await findSubs(b.orgId, b.role, b.uid)).length;
      console.log(`[notify] dryRun org=${b.orgId ?? "-"} role=${b.role ?? "-"} uid=${b.uid ?? "-"} matched=${n}`);
      return json({ ok: true, matched: n });
    }
    if (!b.title) return json({ error: "title required" }, 400);
    // uid = one specific person; otherwise orgId / role are optional filters
    const r = await send({ orgId: b.orgId, role: b.role, uid: b.uid }, b.title, b.body ?? "", b.url ?? "/");
    return json({ ok: r.sent > 0 || r.matched === 0, ...r });
  }

  console.warn(`[req] unknown path ${path}`);
  return json({ error: "not found" }, 404);
}

// =====================================================================
//  Super-admin auth, AI writing (Groq), audience dispatch, schedules
// =====================================================================
const int = (n: number) => ({ integerValue: String(Math.round(n)) });

function fromFs(v: any): any {
  if (!v) return null;
  if ("stringValue" in v) return v.stringValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue" in v) return v.doubleValue;
  if ("booleanValue" in v) return v.booleanValue;
  if ("timestampValue" in v) return Date.parse(v.timestampValue);
  if ("arrayValue" in v) return (v.arrayValue.values ?? []).map(fromFs);
  if ("mapValue" in v) return fromFsFields(v.mapValue.fields ?? {});
  return null;
}
const fromFsFields = (f: Record<string, any>): Record<string, any> =>
  Object.fromEntries(Object.entries(f).map(([k, v]) => [k, fromFs(v)]));

// The caller sends their Firebase login token. Firestore itself validates the token when we read
// their own user record with it, so a fake token cannot pass.
function jwtSub(t: string): string | null {
  try {
    const j = JSON.parse(atob(t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return j.user_id || j.sub || null;
  } catch { return null; }
}
async function requireSuper(req: Request): Promise<boolean> {
  const h = req.headers.get("authorization") ?? "";
  const tok = h.startsWith("Bearer ") ? h.slice(7) : "";
  const uid = tok ? jwtSub(tok) : null;
  if (!uid || !/^[A-Za-z0-9]+$/.test(uid)) return false;
  if (SUPER_UID && uid !== SUPER_UID) return false;
  const r = await fetch(`${DB}/users/${uid}`, { headers: { Authorization: `Bearer ${tok}` } });
  if (!r.ok) return false;
  const d = await r.json();
  return d?.fields?.role?.stringValue === "super_admin";
}

type PInfo = { name: string; batch: string; lastTest: string; lastPct: number | null; daysSince: number | null };

const safeName = (n: unknown) => String(n ?? "").replace(/[^\p{L} ]/gu, "").trim().split(/\s+/)[0]?.slice(0, 20) ?? "";

async function userInfo(uids: string[], withFacts: boolean): Promise<Record<string, PInfo>> {
  const out: Record<string, PInfo> = {};
  for (let i = 0; i < uids.length; i += 100) {
    const chunk = uids.slice(i, i + 100);
    const r = await fetch(`${DB}:batchGet`, {
      method: "POST", headers: await fsHeaders(),
      body: JSON.stringify({ documents: chunk.map((u) => `projects/${SA.project_id}/databases/(default)/documents/users/${u}`) }),
    });
    const rows = await r.json();
    if (!r.ok) { console.error("[users] batchGet failed", r.status, JSON.stringify(rows)); continue; }
    for (const row of rows) {
      if (!row.found) continue;
      const f = fromFsFields(row.found.fields ?? {});
      out[row.found.name.split("/").pop()] = { name: safeName(f.username), batch: String(f.batchName ?? "").slice(0, 40), lastTest: "", lastPct: null, daysSince: null };
    }
  }
  if (withFacts) {
    await Promise.all(Object.keys(out).map(async (uid) => {
      try {
        const r = await fetch(`${DB}:runQuery`, {
          method: "POST", headers: await fsHeaders(),
          body: JSON.stringify({ structuredQuery: { from: [{ collectionId: "results" }], where: { fieldFilter: { field: { fieldPath: "userId" }, op: "EQUAL", value: str(uid) } }, limit: 20 } }),
        });
        const rows = await r.json();
        if (!r.ok) return;
        const docs = rows.filter((x: any) => x.document).map((x: any) => x.document);
        if (!docs.length) return;
        docs.sort((a: any, b: any) => Date.parse(b.createTime) - Date.parse(a.createTime));
        const f = fromFsFields(docs[0].fields ?? {});
        out[uid].lastTest = String(f.testTitle ?? "").slice(0, 60);
        out[uid].lastPct = typeof f.percentage === "number" ? Math.round(f.percentage) : null;
        out[uid].daysSince = Math.max(0, Math.floor((Date.now() - Date.parse(docs[0].createTime)) / 86400000));
      } catch (e) { console.error("[users] facts failed", String(e)); }
    }));
  }
  return out;
}

// ---------- Groq ----------
const RULES = `You write push notifications for "Good for You", a test-practice app for students in India. ` +
  `Rules: title at most 45 characters, body at most 110 characters. You may use one or two fitting emojis, no hashtags, no quotation marks around the text. ` +
  `Warm, direct and motivating, never guilt-tripping. Use ONLY the facts you are given; never invent scores, ranks, test names, dates or deadlines. ` +
  `Reply with JSON only.`;

async function groqJson(system: string, user: string): Promise<any> {
  const call = async (jsonMode: boolean) => {
    const body: Record<string, unknown> = {
      model: GROQ_MODEL, temperature: 0.8, max_tokens: 1500,
      messages: [{ role: "system", content: system }, { role: "user", content: user }],
    };
    if (jsonMode) body.response_format = { type: "json_object" };
    if (GROQ_MODEL.startsWith("openai/gpt-oss")) body.reasoning_effort = "low";   // keep thinking short so the answer is not cut off
    return await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST", headers: { "content-type": "application/json", Authorization: `Bearer ${GROQ_KEY}` }, body: JSON.stringify(body),
    });
  };
  let r = await call(true);
  if (r.status === 400) r = await call(false);   // some models reject JSON mode; we extract the JSON ourselves
  if (!r.ok) throw new Error(`groq ${r.status} ${(await r.text()).slice(0, 200)}`);
  const j = await r.json();
  const text: string = j.choices?.[0]?.message?.content ?? "";
  try { return JSON.parse(text); }
  catch {
    const m = text.match(/\{[\s\S]*\}/);
    if (!m) throw new Error("AI reply was not JSON");
    return JSON.parse(m[0]);
  }
}

const stripEmoji = (t: unknown) => String(t ?? "").replace(/\s+/g, " ").trim();   // emojis are allowed now; only tidy the spacing
function cleanMsg(m: any): { title: string; body: string } {
  const title = stripEmoji(m?.title).slice(0, 45), body = stripEmoji(m?.body).slice(0, 140);
  if (!title || !body) throw new Error("AI returned an empty message");
  return { title, body };
}

async function aiOne(instruction: string, p: PInfo | null): Promise<{ title: string; body: string }> {
  const facts: string[] = [];
  facts.push(p?.name ? `Student first name: ${p.name}` : "Name unknown: do not use a name");
  if (p?.batch) facts.push(`Batch: ${p.batch}`);
  if (p?.lastTest) facts.push(`Last test taken: "${p.lastTest}"${p.lastPct !== null ? `, scored ${p.lastPct} percent` : ""}${p.daysSince !== null ? `, ${p.daysSince} day(s) ago` : ""}`);
  const j = await groqJson(RULES + ` Format: {"title":"...","body":"..."}.`, `Instruction from the admin: ${instruction}\nFacts about this student:\n${facts.join("\n")}`);
  return cleanMsg(j);
}

async function aiVariants(instruction: string): Promise<{ title: string; body: string }[]> {
  const j = await groqJson(
    RULES + ` Write 3 different versions. In every body, include the placeholder {name} exactly once where the student's first name goes (for example "{name}, ..."). ` +
      `Format: {"variants":[{"title":"...","body":"..."},{"title":"...","body":"..."},{"title":"...","body":"..."}]}.`,
    `Instruction from the admin: ${instruction}`);
  const v = (j.variants ?? []).map((x: any) => {
    const m = cleanMsg(x);
    return { title: m.title, body: m.body.includes("{name}") ? m.body : `{name}, ${m.body}` };
  });
  if (!v.length) throw new Error("AI returned no variants");
  return v;
}

const FALLBACKS = [
  { title: "Good for You", body: "{name}, a little practice every day beats last-minute stress. Take a test today." },
  { title: "Time to practise", body: "{name}, your next rank is one test away. Start now." },
  { title: "Keep going", body: "{name}, practise today and move closer to your goal." },
];

function fill(text: string, name: string): string {
  if (name) return text.replaceAll("{name}", name);
  const t = text.replace(/\{name\}[,:]?\s*/g, "").trim();
  return t ? t[0].toUpperCase() + t.slice(1) : t;
}

// ---------- Dispatch ----------
type Audience = { type: "all" | "org" | "users"; orgId?: string; role?: string; uids?: string[] };
type Spec = { audience: Audience; mode: "ai" | "fixed"; instruction?: string; title?: string; body?: string; url?: string; dryRun?: boolean };

function cleanSpec(b: any): Spec | string {
  const a = b.audience ?? {};
  if (!["all", "org", "users"].includes(a.type)) return "audience.type must be all, org or users";
  if (a.type === "org" && !a.orgId) return "orgId required";
  if (a.type === "users" && !(a.uids ?? []).length) return "pick at least one person";
  const mode = b.mode === "ai" ? "ai" : "fixed";
  const spec: Spec = {
    audience: { type: a.type, orgId: a.orgId ? String(a.orgId).toUpperCase() : undefined, role: a.role ? String(a.role).toLowerCase() : undefined, uids: (a.uids ?? []).map(String).slice(0, 200) },
    mode, url: String(b.url ?? "/").startsWith("/") ? String(b.url ?? "/") : "/", dryRun: !!b.dryRun,
  };
  if (mode === "ai") { spec.instruction = String(b.instruction ?? "").trim().slice(0, 500); if (!spec.instruction) return "instruction required"; }
  else { spec.title = String(b.title ?? "").trim().slice(0, 60); spec.body = String(b.body ?? "").trim().slice(0, 150); if (!spec.title) return "title required"; }
  return spec;
}

async function resolveSubs(a: Audience): Promise<Sub[]> {
  if (a.type === "users") {
    const all = await Promise.all((a.uids ?? []).slice(0, 200).map((u) => findSubs(undefined, undefined, u)));
    return all.flat();
  }
  if (a.type === "org") return findSubs(a.orgId, a.role);
  return findSubs(undefined, a.role);
}

async function dispatch(spec: Spec) {
  const subs = await resolveSubs(spec.audience);
  if (spec.dryRun) return { ok: true, matched: subs.length };
  if (!subs.length) return { ok: true, matched: 0, sent: 0, failed: 0, removed: 0 };

  const uids = [...new Set(subs.map((s) => s.uid).filter(Boolean))];
  const few = uids.length <= 15;
  const wantsName = spec.mode === "ai" || /\{name\}/.test((spec.title ?? "") + (spec.body ?? ""));
  const info = wantsName && uids.length ? await userInfo(uids, spec.mode === "ai" && few) : {};

  const personal: Record<string, { title: string; body: string }> = {};
  let variants = FALLBACKS, ai = false, fallback = false, aiError = "";
  if (spec.mode === "ai") {
    try {
      if (!GROQ_KEY) throw new Error("GROQ_API_KEY is not set");
      if (few) {
        await Promise.all(uids.map(async (u) => { personal[u] = await aiOne(spec.instruction!, info[u] ?? null); }));
        if (subs.some((s) => !s.uid)) personal[""] = await aiOne(spec.instruction!, null);
      } else {
        variants = await aiVariants(spec.instruction!);
      }
      ai = true;
    } catch (e) {
      fallback = true; aiError = String(e instanceof Error ? e.message : e);
      console.error("[ai] failed, using fallback messages:", aiError);
    }
  }

  const pick = (key: string) => variants[parseInt(key.slice(0, 6), 16) % variants.length] ?? variants[0];
  let sample = { title: "", body: "" };
  const items: Item[] = subs.map((sub) => {
    const nm = info[sub.uid]?.name ?? "";
    let m: { title: string; body: string };
    if (spec.mode === "ai") m = personal[sub.uid] ?? (few && personal[""]) ?? pick(sub.id);
    else m = { title: spec.title!, body: spec.body ?? "" };
    const out = { title: fill(m.title, nm), body: fill(m.body, nm) };
    if (!sample.title) sample = out;
    return { sub, payload: JSON.stringify({ ...out, url: spec.url ?? "/" }) };
  });
  const r = await sendItems(items);
  return { ok: r.sent > 0, ...r, ai, fallback, aiError, sample };
}

// ---------- Scheduled notifications ("alarms") ----------
const SCHED = "scheduledNotifs";
type Repeat = { kind: "once" | "daily" | "weekly"; days?: number[]; hour?: number; minute?: number; tzOffsetMin?: number };

// Next run strictly after `afterMs`, using the time of day the admin picked in their own timezone.
function computeNext(rep: Repeat, afterMs: number): number | null {
  if (!rep || rep.kind === "once") return null;
  const tz = rep.tzOffsetMin ?? 0, h = rep.hour ?? 0, m = rep.minute ?? 0;
  const local = new Date(afterMs + tz * 60000);
  for (let i = 0; i <= 8; i++) {
    const candLocal = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate() + i, h, m);
    const cand = candLocal - tz * 60000;
    if (cand <= afterMs) continue;
    if (rep.kind === "daily" || (rep.days ?? []).includes(new Date(candLocal).getUTCDay())) return cand;
  }
  return null;
}

async function patchSchedule(id: string, fields: Record<string, unknown>) {
  const mask = Object.keys(fields).map((k) => `updateMask.fieldPaths=${k}`).join("&");
  const r = await fetch(`${DB}/${SCHED}/${id}?${mask}`, { method: "PATCH", headers: await fsHeaders(), body: JSON.stringify({ fields }) });
  if (!r.ok) console.error("[sched] patch failed", id, r.status, await r.text());
  return r.ok;
}

async function activeSchedules(): Promise<any[]> {
  const res = await fetch(`${DB}:runQuery`, {
    method: "POST", headers: await fsHeaders(),
    body: JSON.stringify({ structuredQuery: { from: [{ collectionId: SCHED }], where: { fieldFilter: { field: { fieldPath: "status" }, op: "EQUAL", value: str("active") } } } }),
  });
  const rows = await res.json();
  if (!res.ok) throw new Error("schedule query failed " + res.status + " " + JSON.stringify(rows));
  return rows.filter((r: any) => r.document).map((r: any) => ({ id: r.document.name.split("/").pop(), ...fromFsFields(r.document.fields ?? {}) }));
}

// (Every-minute scheduler removed: notifications are now sent manually from the super admin page.)

// Casual practice reminder to students: Mon & Thu, 17:00 IST (11:30 UTC). Written by AI with each student's name.
Deno.cron("practice-reminder", "30 11 * * 1,4", async () => {
  console.log("[cron] sending practice reminder");
  await dispatch({
    audience: { type: "all", role: "student" }, mode: "ai", url: "/dashboard.html",
    instruction: "A short friendly nudge to practise a test today. Encouraging, a little different each time, no pressure.",
  });
});

// =====================================================================
//  Firebase Authentication user management (super admin only)
//  Uses its own token so the Firestore/notification token is untouched.
// =====================================================================
let authCached = { token: "", exp: 0 };
async function authAccessToken(): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (authCached.token && authCached.exp > now + 60) return authCached.token;
  const head = b64u(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64u(JSON.stringify({
    iss: SA.client_email,
    scope: "https://www.googleapis.com/auth/identitytoolkit",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  }));
  const der = Uint8Array.from(
    atob(SA.private_key.replace(/-----[^-]+-----/g, "").replace(/\s/g, "")),
    (c) => c.charCodeAt(0),
  );
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(`${head}.${claim}`));
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${head}.${claim}.${b64u(sig)}`,
  });
  const j = await r.json();
  if (!j.access_token) throw new Error("auth token failed: " + JSON.stringify(j));
  authCached = { token: j.access_token, exp: now + 3300 };
  return j.access_token;
}

async function authAdmin(req: Request, path: string, b: any): Promise<Response> {
  const base = `https://identitytoolkit.googleapis.com/v1/projects/${SA.project_id}/accounts`;
  const H = { Authorization: `Bearer ${await authAccessToken()}`, "content-type": "application/json" };
  const myUid = jwtSub((req.headers.get("authorization") ?? "").slice(7));
  const uid = String(b.uid ?? "");
  const call = async (url: string, init?: RequestInit) => {
    const r = await fetch(url, { headers: H, ...init });
    const j = await r.json().catch(() => ({}));
    return r.ok ? json({ ok: true, ...j }) : json({ error: j?.error?.message ?? "Auth error " + r.status }, 400);
  };
  if (path === "/admin/auth/list") {
    const q = new URLSearchParams({ maxResults: "100" });
    if (b.pageToken) q.set("nextPageToken", String(b.pageToken));
    return call(`${base}:batchGet?${q}`);
  }
  if (!/^[A-Za-z0-9]+$/.test(uid)) return json({ error: "valid uid required" }, 400);
  if (path === "/admin/auth/delete") {
    if (uid === myUid) return json({ error: "you cannot delete your own login" }, 400);
    return call(`${base}:delete`, { method: "POST", body: JSON.stringify({ localId: uid }) });
  }
  if (path === "/admin/auth/update") {
    if (uid === myUid && b.disabled === true) return json({ error: "you cannot disable your own login" }, 400);
    const f: Record<string, unknown> = { localId: uid };
    if (b.email) f.email = String(b.email);
    if (b.password) f.password = String(b.password);
    if (b.displayName !== undefined) f.displayName = String(b.displayName);
    if (typeof b.disabled === "boolean") f.disableUser = b.disabled;
    return call(`${base}:update`, { method: "POST", body: JSON.stringify(f) });
  }
  return json({ error: "not found" }, 404);
}
