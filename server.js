'use strict';
/**
 * GZ AI Beast remote runtime.
 * The phone keeps NO toolchain: it sends the project's changed files + one shell command, this server runs it
 * in a per-project workspace and streams the output back, then returns only the files the command created/changed/deleted.
 * Zero dependencies (Node >= 18).
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawn, spawnSync } = require('child_process');

const CFG = {
  port: parseInt(process.env.PORT || '8080', 10),
  host: process.env.HOST || '0.0.0.0',          // Termux on the same phone: HOST=127.0.0.1 so nothing else can reach it
  key: process.env.BEAST_KEY || '',
  root: path.resolve(process.env.WORK_ROOT || path.join(os.tmpdir(), 'beast-work')),
  maxBody: parseInt(process.env.MAX_BODY_MB || '64', 10) * 1024 * 1024,
  maxReturn: parseInt(process.env.MAX_RETURN_MB || '32', 10) * 1024 * 1024,
  maxTimeout: parseInt(process.env.MAX_TIMEOUT_MS || '900000', 10),
  idleMs: parseInt(process.env.PROJECT_IDLE_MS || String(6 * 3600 * 1000), 10),
  concurrency: parseInt(process.env.CONCURRENCY || '2', 10),
  // Per-user limits for people signed in with Google (the owner key is exempt)
  userCmdsPerHour: parseInt(process.env.USER_CMDS_PER_HOUR || '120', 10),
  userConcurrency: parseInt(process.env.USER_CONCURRENCY || '1', 10),
  allowGoogle: process.env.ALLOW_GOOGLE !== '0',
  // Google answers this only for a valid token; permissionId is the user's stable id. Tests point it at a local mock.
  googleVerifyUrl: process.env.GOOGLE_VERIFY_URL || 'https://www.googleapis.com/drive/v3/about?fields=user(permissionId)',
};
// Folders that stay on the server between commands and are never synced to the phone (dependency/build caches).
const IGNORE = new Set(['node_modules', '.gradle', '.cache', '__pycache__', '.venv', 'venv', '.npm', '.m2']);
const TOOLS = ['bash', 'sh', 'git', 'python3', 'pip', 'node', 'npm', 'java', 'javac', 'gradle', 'mvn', 'gcc', 'g++', 'make', 'cmake', 'zip', 'unzip', 'curl', 'wget', 'tar', 'jq', 'sed', 'awk'];

if (!CFG.key || CFG.key.length < 16) { console.error('BEAST_KEY (>=16 chars) is required'); process.exit(1); }
fs.mkdirSync(CFG.root, { recursive: true });

let active = 0;
const lastUse = new Map();

const tokenCache = new Map();   // sha256(token) -> {uid, until}
const userActive = new Map();   // uid -> running commands
const userHits = new Map();     // uid -> timestamps of commands in the last hour

/** Who is calling? 'owner' for the server key, 'g<hash>' for a valid Google sign-in token, null otherwise. */
async function identify(req) {
  const m = /^Bearer (.+)$/.exec(req.headers['authorization'] || '');
  if (!m) return null;
  const token = m[1];
  const a = crypto.createHash('sha256').update(token).digest();
  const b = crypto.createHash('sha256').update(CFG.key).digest();
  if (crypto.timingSafeEqual(a, b)) return 'owner';
  if (!CFG.allowGoogle || token.length < 20 || token.length > 4096) return null;
  const ck = a.toString('hex'), hit = tokenCache.get(ck);
  if (hit && hit.until > Date.now()) return hit.uid;
  try {
    const r = await fetch(CFG.googleVerifyUrl, { headers: { Authorization: 'Bearer ' + token }, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return null;
    const j = await r.json();
    const id = j && j.user && j.user.permissionId;
    if (!id) return null;
    const uid = 'g' + crypto.createHash('sha256').update(String(id)).digest('hex').slice(0, 24);
    if (tokenCache.size > 5000) tokenCache.clear();
    tokenCache.set(ck, { uid, until: Date.now() + 5 * 60 * 1000 });
    return uid;
  } catch (e) { return null; }
}
function rateOk(uid) {
  if (uid === 'owner') return true;
  const now = Date.now(), arr = (userHits.get(uid) || []).filter(t => now - t < 3600 * 1000);
  if (arr.length >= CFG.userCmdsPerHour) { userHits.set(uid, arr); return false; }
  arr.push(now); userHits.set(uid, arr); return true;
}
function validProject(id) { return typeof id === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id) && !id.includes('..'); }
function validRel(rel) {
  if (typeof rel !== 'string' || !rel || rel.length > 400 || rel.includes('\0') || rel.includes('\\')) return false;
  if (rel.startsWith('/')) return false;
  const parts = rel.split('/');
  return parts.every(p => p && p !== '.' && p !== '..') && !IGNORE.has(parts[0]);
}
function inside(base, target) { const r = path.relative(base, target); return r && !r.startsWith('..') && !path.isAbsolute(r); }

function walk(dir, base, out) {
  let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
  for (const e of ents) {
    const abs = path.join(dir, e.name);
    const rel = path.relative(base, abs).split(path.sep).join('/');
    if (IGNORE.has(e.name)) continue;
    if (e.isSymbolicLink()) continue;
    if (e.isDirectory()) walk(abs, base, out);
    else if (e.isFile()) out.push({ rel, abs });
  }
}
const hashCache = new Map(); // abs -> {m,s,h}
function sha(abs) {
  const st = fs.statSync(abs);
  const c = hashCache.get(abs);
  if (c && c.m === st.mtimeMs && c.s === st.size) return c.h;
  const h = crypto.createHash('sha256').update(fs.readFileSync(abs)).digest('hex');
  hashCache.set(abs, { m: st.mtimeMs, s: st.size, h });
  return h;
}
function snapshot(dir) {
  const files = []; walk(dir, dir, files);
  const m = {}; for (const f of files) m[f.rel] = sha(f.abs);
  return m;
}
function rmEmptyDirs(dir, base) {
  let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
  for (const e of ents) if (e.isDirectory() && !IGNORE.has(e.name)) rmEmptyDirs(path.join(dir, e.name), base);
  if (dir !== base) { try { fs.rmdirSync(dir); } catch (e) { /* not empty */ } }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on('data', c => { n += c.length; if (n > CFG.maxBody) { reject(Object.assign(new Error('body too large'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function json(res, code, obj) { const b = Buffer.from(JSON.stringify(obj)); res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': b.length }); res.end(b); }

// Termux needs a few of its own variables (LD_PRELOAD=termux-exec makes '#!/usr/bin/env' scripts like npm work); nothing secret is forwarded.
const PASS_ENV = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'PREFIX', 'TMPDIR', 'ANDROID_ROOT', 'ANDROID_DATA', 'TERMUX_VERSION'];
function cleanEnv(home) {
  const extra = {}; for (const k of PASS_ENV) if (process.env[k]) extra[k] = process.env[k];
  return { ...extra, PATH: process.env.BEAST_PATH || process.env.PATH || '/usr/local/bin:/usr/bin:/bin', HOME: home, LANG: 'C.UTF-8', TERM: 'dumb', CI: '1', npm_config_cache: path.join(home, '.npm'), PIP_CACHE_DIR: path.join(home, '.pip') };
}

async function exec(req, res, uid) {
  let body;
  try { body = JSON.parse((await readBody(req)).toString('utf8')); } catch (e) { return json(res, e.status || 400, { error: e.status ? e.message : 'invalid JSON' }); }
  const { project, command } = body;
  if (!validProject(project)) return json(res, 400, { error: 'invalid project id' });
  if (typeof command !== 'string' || !command.trim() || command.length > 20000) return json(res, 400, { error: 'invalid command' });
  const manifest = body.manifest && typeof body.manifest === 'object' ? body.manifest : {};
  const files = body.files && typeof body.files === 'object' ? body.files : {};
  const timeoutMs = Math.min(Math.max(parseInt(body.timeoutMs || '120000', 10) || 120000, 1000), CFG.maxTimeout);

  const base = path.join(CFG.root, uid, project);
  const dir = path.join(base, 'work');
  const home = path.join(base, 'home');
  fs.mkdirSync(dir, { recursive: true }); fs.mkdirSync(home, { recursive: true });
  lastUse.set(uid + '/' + project, Date.now());

  // 1. bring the workspace to exactly what the phone has
  for (const rel of Object.keys(manifest)) if (!validRel(rel)) return json(res, 400, { error: 'invalid path in manifest: ' + rel });
  for (const rel of Object.keys(files)) if (!validRel(rel)) return json(res, 400, { error: 'invalid path in files: ' + rel });
  const have = snapshot(dir);
  for (const rel of Object.keys(have)) if (!(rel in manifest)) { try { fs.unlinkSync(path.join(dir, rel)); } catch (e) { /* gone */ } }
  for (const [rel, b64] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    if (!inside(dir, abs)) return json(res, 400, { error: 'path escapes workspace' });
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, Buffer.from(String(b64), 'base64'));
  }
  const now = snapshot(dir);
  const need = Object.keys(manifest).filter(rel => now[rel] !== manifest[rel]);
  if (need.length) return json(res, 409, { need });
  rmEmptyDirs(dir, dir);
  const before = snapshot(dir);

  // 2. run it
  if (active >= CFG.concurrency) return json(res, 429, { error: 'server busy, try again in a moment' });
  if (uid !== 'owner' && (userActive.get(uid) || 0) >= CFG.userConcurrency) return json(res, 429, { error: 'you already have a command running' });
  if (!rateOk(uid)) return json(res, 429, { error: 'hourly command limit reached for your account' });
  active++; userActive.set(uid, (userActive.get(uid) || 0) + 1);
  res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' });
  const send = o => { if (!res.writableEnded) res.write(JSON.stringify(o) + '\n'); };
  const child = spawn('bash', ['-c', command], { cwd: dir, env: cleanEnv(home), detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let timedOut = false, finished = false;
  const killTree = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch (e) { try { child.kill('SIGKILL'); } catch (e2) { /* done */ } } };
  const timer = setTimeout(() => { timedOut = true; killTree(); }, timeoutMs);
  res.on('close', () => { if (!finished) killTree(); });       // phone cancelled / dropped: stop the command
  const pump = (stream, kind) => {
    let buf = '';
    stream.setEncoding('utf8');
    stream.on('data', d => {
      buf += d; let i;
      while ((i = buf.indexOf('\n')) >= 0) { send({ t: kind, l: buf.slice(0, i).slice(0, 4000) }); buf = buf.slice(i + 1); }
      if (buf.length > 8000) { send({ t: kind, l: buf.slice(0, 4000) }); buf = ''; }
    });
    stream.on('end', () => { if (buf) send({ t: kind, l: buf.slice(0, 4000) }); });
  };
  pump(child.stdout, 'out'); pump(child.stderr, 'err');
  const code = await new Promise(resolve => child.on('close', c => resolve(c == null ? -1 : c)));
  finished = true; clearTimeout(timer); active--; userActive.set(uid, Math.max(0, (userActive.get(uid) || 1) - 1));

  // 3. return only what changed
  const after = snapshot(dir);
  const changed = {}, deleted = [], skipped = [];
  let total = 0;
  for (const rel of Object.keys(after)) {
    if (before[rel] === after[rel]) continue;
    const buf = fs.readFileSync(path.join(dir, rel));
    if (total + buf.length > CFG.maxReturn) { skipped.push(rel); continue; }
    total += buf.length; changed[rel] = buf.toString('base64');
  }
  for (const rel of Object.keys(before)) if (!(rel in after)) deleted.push(rel);
  send({ t: 'done', exit: code, timedOut, changed, deleted, skipped });
  res.end();
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (req.method === 'GET' && url.pathname === '/') return json(res, 200, { ok: true, service: 'beast-remote-runtime' });
    const uid = await identify(req);
    if (!uid) return json(res, 401, { error: 'bad key or Google sign-in token' });
    if (req.method === 'GET' && url.pathname === '/v1/health') {
      const tools = TOOLS.filter(t => spawnSync('bash', ['-c', 'command -v ' + t]).status === 0);
      return json(res, 200, { ok: true, tools, active });
    }
    if (req.method === 'POST' && url.pathname === '/v1/exec') {
      return await exec(req, res, uid);
    }
    const m = /^\/v1\/project\/([^/]+)$/.exec(url.pathname);
    if (req.method === 'DELETE' && m) {
      if (!validProject(m[1])) return json(res, 400, { error: 'invalid project id' });
      fs.rmSync(path.join(CFG.root, uid, m[1]), { recursive: true, force: true });
      return json(res, 200, { ok: true });
    }
    return json(res, 404, { error: 'not found' });
  } catch (e) {
    if (!res.headersSent) json(res, e.status || 500, { error: String(e.message || e) }); else res.end();
  }
});

setInterval(() => {   // free server disk: drop workspaces nobody used for a while (the phone/Drive hold the real copy)
  const now = Date.now();
  let users = []; try { users = fs.readdirSync(CFG.root); } catch (e) { return; }
  for (const u of users) {
    const ud = path.join(CFG.root, u);
    let projects = []; try { projects = fs.readdirSync(ud); } catch (e) { continue; }
    for (const p of projects) {
      const pd = path.join(ud, p);
      let last = lastUse.get(u + '/' + p); if (!last) { try { last = fs.statSync(pd).mtimeMs; } catch (e) { last = 0; } }
      if (now - last > CFG.idleMs) fs.rmSync(pd, { recursive: true, force: true });
    }
    try { if (!fs.readdirSync(ud).length) fs.rmdirSync(ud); } catch (e) { /* busy */ }
  }
}, 10 * 60 * 1000).unref();

if (require.main === module) server.listen(CFG.port, CFG.host, () => console.log('beast-remote-runtime on :' + CFG.port));
module.exports = { server, CFG };
