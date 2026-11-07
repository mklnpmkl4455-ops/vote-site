const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) { console.error('ต้องตั้งค่า ADMIN_PASSWORD ก่อนเริ่มเซิร์ฟเวอร์'); process.exit(1); }
const SECRET = process.env.SESSION_SECRET || crypto.createHash('sha256').update('s:' + ADMIN_PASSWORD).digest('hex');
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const PUB = __dirname;

const DEFAULT = {
  title: '🎬 อยากดูเรื่องไหนต่อ?',
  subtitle: 'แตะเพื่อโหวตหนังเรื่องต่อไปที่อยากให้ทำ',
  options: [
    { id: 'a', t: 'ติดเกาะ ภาค 2', d: 'ผจญภัยต่อจากห้องทดลองใต้ดิน' },
    { id: 'b', t: 'เรื่องลึกลับในโรงเรียนร้าง', d: 'สืบสวน ระทึกขวัญ' },
    { id: 'c', t: 'ผจญภัยใต้ทะเลลึก', d: 'แฟนตาซี ผจญภัย' }
  ],
  votes: {}
};
let state;
try { state = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { state = JSON.parse(JSON.stringify(DEFAULT)); }
function save() { try { fs.writeFileSync(DATA_FILE, JSON.stringify(state)); } catch (e) { console.error('save failed', e.message); } }

const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const safeEq = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return o;
}
function isAdmin(req) {
  const t = cookies(req).adm || '';
  const [exp, sig] = t.split('.');
  return !!(exp && sig && Number(exp) > Date.now() && safeEq(sig, sign('adm:' + exp)));
}
const secure = req => (req.headers['x-forwarded-proto'] || '') === 'https' ? '; Secure' : '';
function send(res, code, obj, headers = {}) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(obj));
}
function body(req) {
  return new Promise((resolve, reject) => {
    let s = '';
    req.on('data', c => { s += c; if (s.length > 20000) { reject(new Error('too big')); req.destroy(); } });
    req.on('end', () => { try { resolve(s ? JSON.parse(s) : {}); } catch (e) { reject(e); } });
  });
}
const ip = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const attempts = new Map();
function pollView(vid) {
  const counts = {}; let total = 0;
  state.options.forEach(o => counts[o.id] = 0);
  Object.values(state.votes).forEach(id => { if (id in counts) { counts[id]++; total++; } });
  return { title: state.title, subtitle: state.subtitle, options: state.options, counts, total, mine: state.votes[vid] || null };
}
const clip = (s, n) => String(s || '').trim().slice(0, n);

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  try {
    if (p === '/api/poll' && req.method === 'GET') {
      let vid = cookies(req).vid, h = {};
      if (!vid) { vid = crypto.randomBytes(16).toString('hex'); h['Set-Cookie'] = `vid=${vid}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax${secure(req)}`; }
      return send(res, 200, pollView(vid), h);
    }
    if (p === '/api/vote' && req.method === 'POST') {
      const vid = cookies(req).vid;
      if (!vid) return send(res, 400, { error: 'no_session' });
      const { optionId } = await body(req);
      if (!state.options.some(o => o.id === optionId)) return send(res, 400, { error: 'bad_option' });
      state.votes[vid] = optionId; save();
      return send(res, 200, pollView(vid));
    }
    if (p === '/api/admin/login' && req.method === 'POST') {
      const k = ip(req), a = attempts.get(k) || { n: 0, t: Date.now() };
      if (Date.now() - a.t > 15 * 60000) { a.n = 0; a.t = Date.now(); }
      if (a.n >= 8) return send(res, 429, { error: 'too_many' });
      const { password } = await body(req);
      const ok = typeof password === 'string' && safeEq(sign(password), sign(ADMIN_PASSWORD));
      if (!ok) { a.n++; attempts.set(k, a); return send(res, 401, { error: 'wrong_password' }); }
      attempts.delete(k);
      const exp = Date.now() + 12 * 3600 * 1000;
      return send(res, 200, { ok: true }, { 'Set-Cookie': `adm=${exp}.${sign('adm:' + exp)}; Path=/; Max-Age=43200; HttpOnly; SameSite=Strict${secure(req)}` });
    }
    if (p === '/api/admin/logout' && req.method === 'POST') {
      return send(res, 200, { ok: true }, { 'Set-Cookie': 'adm=; Path=/; Max-Age=0; HttpOnly' });
    }
    if (p.startsWith('/api/admin/')) {
      if (!isAdmin(req)) return send(res, 401, { error: 'unauthorized' });
      if (p === '/api/admin/me') return send(res, 200, pollView(''));
      if (p === '/api/admin/poll' && req.method === 'PUT') {
        const b = await body(req);
        const opts = (Array.isArray(b.options) ? b.options : []).map(o => ({
          id: /^[a-z0-9]{1,20}$/i.test(o.id || '') ? o.id : 'o' + crypto.randomBytes(4).toString('hex'),
          t: clip(o.t, 80), d: clip(o.d, 120)
        })).filter(o => o.t).slice(0, 12);
        if (opts.length < 2) return send(res, 400, { error: 'need_two' });
        state.title = clip(b.title, 80) || DEFAULT.title;
        state.subtitle = clip(b.subtitle, 140);
        state.options = opts;
        const ids = new Set(opts.map(o => o.id));
        for (const k of Object.keys(state.votes)) if (!ids.has(state.votes[k])) delete state.votes[k];
        save();
        return send(res, 200, pollView(''));
      }
      if (p === '/api/admin/reset' && req.method === 'POST') { state.votes = {}; save(); return send(res, 200, pollView('')); }
      return send(res, 404, { error: 'not_found' });
    }
    // static
    const file = p === '/' ? 'index.html' : p === '/admin' ? 'admin.html' : null;
    if (file) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(path.join(PUB, file)));
    }
    send(res, 404, { error: 'not_found' });
  } catch (e) { send(res, 400, { error: 'bad_request' }); }
});
server.listen(PORT, () => console.log('รันที่พอร์ต ' + PORT));
