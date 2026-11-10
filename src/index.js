// Webtool quản lý thu chi trên SePay (Cloudflare Workers + D1)
// - Nhận webhook biến động số dư từ SePay (xác thực HMAC-SHA256 hoặc API Key)
// - Đối soát định kỳ qua SePay API v2 để không sót giao dịch
// - API cho giao diện: tổng quan, giao dịch, danh mục, quy tắc, thu tiền QR, người dùng

const SEPAY_BASE = {
  production: 'https://userapi.sepay.vn/v2',
  sandbox: 'https://userapi-sandbox.sepay.vn/v2',
};
const ROLE_LEVEL = { viewer: 1, editor: 2, admin: 3 };
const SESSION_HOURS = 24 * 7;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith('/api/')) return await handleApi(request, env, ctx, url);
      return env.ASSETS.fetch(request);
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.message }, err.status);
      console.error(err);
      return json({ error: 'Lỗi máy chủ: ' + (err.message || err) }, 500);
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(syncFromSepay(env).catch((e) => console.error('sync failed', e)));
  },
};

// Cấu hình SePay: ưu tiên giá trị nhập ở trang Thiết lập SePay (lưu D1), sau đó tới biến môi trường
async function cfg(env) {
  if (env._cfg) return env._cfg;
  const rows = (await env.DB.prepare("SELECT key, value FROM settings WHERE key IN ('sepay_api_token','sepay_webhook_secret','sepay_env','webhook_auth','session_secret')").all()).results;
  const s = Object.fromEntries(rows.map((r) => [r.key, r.value]));
  let sessionSecret = env.SESSION_SECRET || s.session_secret;
  if (!sessionSecret) {
    sessionSecret = toHex(crypto.getRandomValues(new Uint8Array(32)));
    await env.DB.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES ('session_secret', ?)").bind(sessionSecret).run();
    sessionSecret = (await env.DB.prepare("SELECT value FROM settings WHERE key='session_secret'").first()).value;
  }
  env._cfg = {
    apiToken: s.sepay_api_token || env.SEPAY_API_TOKEN || '',
    webhookSecret: s.sepay_webhook_secret || env.SEPAY_WEBHOOK_SECRET || '',
    sepayEnv: s.sepay_env || env.SEPAY_ENV || 'sandbox',
    webhookAuth: s.webhook_auth || env.WEBHOOK_AUTH || 'hmac',
    sessionSecret,
  };
  return env._cfg;
}

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });
}

// ---------------------------------------------------------------- router
async function handleApi(request, env, ctx, url) {
  const p = url.pathname;
  const m = request.method;

  // Webhook SePay: công khai, tự xác thực bằng chữ ký
  if (p === '/api/sepay/webhook' && m === 'POST') return handleWebhook(request, env);

  if (p === '/api/login' && m === 'POST') return login(request, env);
  if (p === '/api/logout' && m === 'POST')
    return json({ ok: true }, 200, { 'set-cookie': 'sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0' });

  const user = await currentUser(request, env);
  if (!user) throw new HttpError(401, 'Chưa đăng nhập');
  const need = (role) => {
    if (ROLE_LEVEL[user.role] < ROLE_LEVEL[role]) throw new HttpError(403, 'Không đủ quyền');
  };
  // Chống CSRF đơn giản: request ghi phải là JSON từ cùng origin
  if (m !== 'GET') {
    const origin = request.headers.get('origin');
    if (origin && origin !== url.origin) throw new HttpError(403, 'Sai nguồn gọi');
  }

  if (p === '/api/me') { const c = await cfg(env); return json({ user, sepay_env: c.sepayEnv, webhook_auth: c.webhookAuth, sepay_ready: !!(c.apiToken && (c.webhookSecret || c.webhookAuth === 'none')) }); }

  if (p === '/api/sepay-config' && m === 'GET') { need('admin'); return json(await sepayConfigView(env, url)); }
  if (p === '/api/sepay-config' && m === 'PUT') { need('admin'); return saveSepayConfig(env, await body(request), url); }
  if (p === '/api/sepay-config/test' && m === 'POST') { need('admin'); return json(await testSepay(env)); }

  if (p === '/api/summary' && m === 'GET') return summary(env, url);

  if (p === '/api/transactions' && m === 'GET') return listTransactions(env, url);
  if (p === '/api/transactions' && m === 'POST') { need('editor'); return createManual(env, await body(request), user); }
  let mm;
  if ((mm = p.match(/^\/api\/transactions\/(\d+)$/))) {
    const id = Number(mm[1]);
    if (m === 'PATCH') { need('editor'); return updateTransaction(env, id, await body(request), user); }
    if (m === 'DELETE') { need('editor'); return deleteTransaction(env, id); }
  }
  if (p === '/api/export.csv' && m === 'GET') return exportCsv(env, url);

  if (p === '/api/categories' && m === 'GET') return json(await all(env, 'SELECT * FROM categories ORDER BY type, sort, name'));
  if (p === '/api/categories' && m === 'POST') { need('editor'); return saveCategory(env, await body(request)); }
  if ((mm = p.match(/^\/api\/categories\/(\d+)$/))) {
    need('editor');
    if (m === 'PUT') return saveCategory(env, { ...(await body(request)), id: Number(mm[1]) });
    if (m === 'DELETE') { await run(env, 'DELETE FROM categories WHERE id=?', Number(mm[1])); return json({ ok: true }); }
  }

  if (p === '/api/rules' && m === 'GET') return json(await all(env, 'SELECT * FROM rules ORDER BY priority, id'));
  if (p === '/api/rules' && m === 'POST') { need('editor'); return saveRule(env, await body(request)); }
  if (p === '/api/rules/apply' && m === 'POST') { need('editor'); return json(await reapplyRules(env)); }
  if ((mm = p.match(/^\/api\/rules\/(\d+)$/))) {
    need('editor');
    if (m === 'PUT') return saveRule(env, { ...(await body(request)), id: Number(mm[1]) });
    if (m === 'DELETE') { await run(env, 'DELETE FROM rules WHERE id=?', Number(mm[1])); return json({ ok: true }); }
  }

  if (p === '/api/accounts' && m === 'GET') return json(await all(env, 'SELECT * FROM bank_accounts ORDER BY bank, account_number'));
  if (p === '/api/sync' && m === 'POST') { need('admin'); return json(await syncFromSepay(env)); }
  if (p === '/api/webhook-log' && m === 'GET') { need('admin'); return json(await all(env, 'SELECT * FROM webhook_log ORDER BY id DESC LIMIT 30')); }
  if (p === '/api/sync-log' && m === 'GET') return json(await all(env, 'SELECT * FROM sync_log ORDER BY id DESC LIMIT 20'));

  if (p === '/api/payment-requests' && m === 'GET') return json(await all(env, 'SELECT * FROM payment_requests ORDER BY id DESC LIMIT 500'));
  if (p === '/api/payment-requests' && m === 'POST') { need('editor'); return createPaymentRequest(env, await body(request), user); }
  if ((mm = p.match(/^\/api\/payment-requests\/(\d+)$/)) && m === 'PATCH') {
    need('editor');
    const b = await body(request);
    if (!['pending', 'cancelled'].includes(b.status)) throw new HttpError(400, 'Trạng thái không hợp lệ');
    await run(env, "UPDATE payment_requests SET status=? WHERE id=? AND status!='paid'", b.status, Number(mm[1]));
    return json({ ok: true });
  }

  if (p === '/api/settings' && m === 'GET') return json(await getSettings(env));
  if (p === '/api/settings' && m === 'PUT') { need('admin'); return saveSettings(env, await body(request)); }

  if (p === '/api/users' && m === 'GET') { need('admin'); return json(await all(env, 'SELECT id, username, display_name, role, active, created_at FROM users ORDER BY id')); }
  if (p === '/api/users' && m === 'POST') { need('admin'); return saveUser(env, await body(request)); }
  if ((mm = p.match(/^\/api\/users\/(\d+)$/)) && m === 'PUT') { need('admin'); return saveUser(env, { ...(await body(request)), id: Number(mm[1]) }); }
  if (p === '/api/password' && m === 'POST') return changePassword(env, user, await body(request));

  throw new HttpError(404, 'Không tìm thấy');
}

async function body(request) {
  try { return await request.json(); } catch { throw new HttpError(400, 'Body JSON không hợp lệ'); }
}
const all = async (env, sql, ...args) => (await env.DB.prepare(sql).bind(...args).all()).results;
const first = (env, sql, ...args) => env.DB.prepare(sql).bind(...args).first();
const run = (env, sql, ...args) => env.DB.prepare(sql).bind(...args).run();

// ---------------------------------------------------------------- webhook
async function handleWebhook(request, env) {
  const raw = await request.text();
  let res;
  try {
    res = await processWebhook(request, env, raw);
  } catch (e) {
    res = { status: 500, message: 'Lỗi xử lý: ' + (e.message || e) };
  }
  // Ghi nhật ký mọi lần gọi, kể cả thất bại, để xem ở tab Thiết lập SePay
  try {
    await env.DB.batch([
      env.DB.prepare('INSERT INTO webhook_log (status, message, sepay_id, amount, transfer_type, ip) VALUES (?,?,?,?,?,?)')
        .bind(res.status, res.message || null, res.p?.id != null ? String(res.p.id) : null,
          res.p?.transferAmount != null ? Number(res.p.transferAmount) : null, res.p?.transferType || null,
          request.headers.get('cf-connecting-ip') || null),
      env.DB.prepare('DELETE FROM webhook_log WHERE id <= (SELECT MAX(id) - 1000 FROM webhook_log)'),
    ]);
  } catch (e) { console.error('webhook_log', e); }
  if (res.status === 200) return json({ success: true });
  return json({ success: false, message: res.message }, res.status);
}

async function processWebhook(request, env, raw) {
  const c = await cfg(env);
  const mode = c.webhookAuth;
  const secret = c.webhookSecret;

  let p = null;
  const ct = request.headers.get('content-type') || '';
  if (ct.includes('application/json') || raw.trim().startsWith('{')) {
    try { p = JSON.parse(raw); } catch { return { status: 400, message: 'Body không phải JSON hợp lệ' }; }
  } else {
    p = Object.fromEntries(new URLSearchParams(raw));
  }

  if (mode === 'hmac') {
    const sig = request.headers.get('x-sepay-signature') || '';
    const ts = Number(request.headers.get('x-sepay-timestamp') || 0);
    if (!secret) return { status: 401, p, message: 'Tool chưa có Secret Key webhook' };
    if (!sig || !ts) {
      const auth = request.headers.get('authorization') || '';
      return { status: 401, p, message: auth.startsWith('Apikey') ? 'SePay đang gửi kiểu API Key, nhưng tool chờ HMAC-SHA256. Đổi kiểu xác thực cho khớp.' : 'Thiếu chữ ký HMAC. Trên SePay hãy chọn bảo mật HMAC-SHA256.' };
    }
    if (Math.abs(Date.now() / 1000 - ts) > 300) return { status: 401, p, message: 'Chữ ký quá hạn (lệch giờ > 5 phút)' };
    const expected = 'sha256=' + (await hmacHex(secret, `${ts}.${raw}`));
    if (!timingSafeEqual(expected, sig)) return { status: 401, p, message: 'Sai chữ ký: Secret Key trên SePay khác với trên tool' };
  } else if (mode === 'apikey') {
    const auth = request.headers.get('authorization') || '';
    if (!secret || !auth.startsWith('Apikey ') || !timingSafeEqual(auth.slice(7), secret))
      return { status: 401, p, message: 'Sai API Key webhook' };
  }

  if (!p || !p.id || !p.transferType || p.transferAmount == null) return { status: 400, p, message: 'Thiếu trường bắt buộc (id, transferType, transferAmount)' };

  const r = await ingestTransaction(env, {
    source: 'webhook',
    sepay_webhook_id: Number(p.id),
    reference_code: p.referenceCode || null,
    account_number: p.accountNumber || null,
    bank: p.gateway || null,
    txn_date: p.transactionDate,
    type: p.transferType === 'out' ? 'out' : 'in',
    amount: Math.abs(Number(p.transferAmount)),
    content: p.content || '',
    description: p.description || '',
    code: p.code || null,
    sub_account: p.subAccount || null,
    accumulated: p.accumulated ? Number(p.accumulated) : null,
  });
  return { status: 200, p, message: r.duplicate ? 'OK (đã có, bỏ qua trùng)' : 'OK, đã ghi giao dịch' };
}

// Ghi giao dịch, chống trùng giữa webhook (id số) và API (UUID)
export async function ingestTransaction(env, t) {
  if (!t.txn_date) t.txn_date = vnNow();
  // 1. Trùng theo khóa SePay
  if (t.sepay_webhook_id != null) {
    const e = await first(env, 'SELECT id FROM transactions WHERE sepay_webhook_id=?', t.sepay_webhook_id);
    if (e) return { id: e.id, duplicate: true };
  }
  if (t.sepay_uuid) {
    const e = await first(env, 'SELECT id FROM transactions WHERE sepay_uuid=?', t.sepay_uuid);
    if (e) return { id: e.id, duplicate: true };
  }
  // 2. Trùng chéo nguồn: cùng tài khoản + mã tham chiếu + số tiền + chiều, hoặc cùng thời điểm + nội dung
  let match = null;
  if (t.reference_code) {
    match = await first(env,
      `SELECT id FROM transactions WHERE account_number IS ? AND reference_code=? AND amount=? AND type=? AND source!='manual' LIMIT 1`,
      t.account_number, t.reference_code, t.amount, t.type);
  }
  if (!match) {
    match = await first(env,
      `SELECT id FROM transactions WHERE account_number IS ? AND txn_date=? AND amount=? AND type=? AND IFNULL(content,'')=? AND source!='manual' LIMIT 1`,
      t.account_number, t.txn_date, t.amount, t.type, t.content || '');
  }
  if (match) {
    if (t.sepay_webhook_id != null) await run(env, 'UPDATE transactions SET sepay_webhook_id=? WHERE id=? AND sepay_webhook_id IS NULL', t.sepay_webhook_id, match.id);
    if (t.sepay_uuid) await run(env, 'UPDATE transactions SET sepay_uuid=? WHERE id=? AND sepay_uuid IS NULL', t.sepay_uuid, match.id);
    return { id: match.id, duplicate: true };
  }

  // 3. Phân loại theo quy tắc + khớp yêu cầu thu tiền
  const rules = await activeRules(env);
  const hit = matchRule(rules, t);
  const res = await env.DB.prepare(
    `INSERT OR IGNORE INTO transactions (source, sepay_webhook_id, sepay_uuid, reference_code, account_number, bank, txn_date, type, amount,
      content, description, code, sub_account, accumulated, category_id, tag, note, categorized_by, created_by)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
  ).bind(
    t.source, t.sepay_webhook_id ?? null, t.sepay_uuid ?? null, t.reference_code ?? null, t.account_number ?? null, t.bank ?? null,
    t.txn_date, t.type, t.amount, t.content ?? null, t.description ?? null, t.code ?? null, t.sub_account ?? null,
    t.accumulated ?? null, t.category_id ?? hit?.category_id ?? null, t.tag ?? hit?.tag ?? null, t.note ?? null,
    t.category_id ? 'user' : hit ? 'rule' : null, t.created_by ?? null
  ).run();
  if (!res.meta.changes) return { duplicate: true }; // đua với một request đồng thời
  const id = res.meta.last_row_id;
  if (t.source !== 'manual' && t.type === 'in') await matchPaymentRequest(env, id, t);
  if (t.account_number && t.accumulated) {
    await run(env,
      `INSERT INTO bank_accounts (account_number, bank, balance, last_transaction) VALUES (?,?,?,?)
       ON CONFLICT(account_number) DO UPDATE SET balance=CASE WHEN IFNULL(last_transaction,'')<=excluded.last_transaction THEN excluded.balance ELSE balance END,
         last_transaction=MAX(IFNULL(last_transaction,''), excluded.last_transaction), bank=IFNULL(bank, excluded.bank)`,
      t.account_number, t.bank, t.accumulated, t.txn_date);
  }
  return { id, duplicate: false };
}

// ---------------------------------------------------------------- quy tắc phân loại
export function normalize(s) {
  return String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/đ/g, 'd').replace(/Đ/g, 'D').toLowerCase();
}
async function activeRules(env) {
  return all(env, 'SELECT * FROM rules WHERE active=1 ORDER BY priority, id');
}
export function matchRule(rules, t) {
  const text = normalize(`${t.content || ''} ${t.description || ''} ${t.code || ''}`);
  for (const r of rules) {
    if (r.transfer_type !== 'any' && r.transfer_type !== t.type) continue;
    if (r.match_type === 'regex') {
      try { if (new RegExp(r.pattern, 'i').test(text)) return r; } catch { /* regex lỗi thì bỏ qua */ }
    } else {
      const parts = normalize(r.pattern).split('|').map((s) => s.trim()).filter(Boolean);
      if (parts.some((x) => text.includes(x))) return r;
    }
  }
  return null;
}
async function reapplyRules(env) {
  const rules = await activeRules(env);
  const rows = await all(env, "SELECT id, type, content, description, code FROM transactions WHERE IFNULL(categorized_by,'')!='user'");
  let updated = 0;
  const stmts = [];
  for (const t of rows) {
    const hit = matchRule(rules, t);
    stmts.push(env.DB.prepare('UPDATE transactions SET category_id=?, tag=COALESCE(?, tag), categorized_by=? WHERE id=?')
      .bind(hit?.category_id ?? null, hit?.tag ?? null, hit ? 'rule' : null, t.id));
    if (hit) updated++;
  }
  for (let i = 0; i < stmts.length; i += 100) await env.DB.batch(stmts.slice(i, i + 100));
  return { scanned: rows.length, categorized: updated };
}

// ---------------------------------------------------------------- thu tiền QR
async function matchPaymentRequest(env, txnId, t) {
  const pending = await all(env, "SELECT * FROM payment_requests WHERE status='pending'");
  if (!pending.length) return;
  const hay = normalize(`${t.code || ''} ${t.content || ''}`).replace(/[^a-z0-9]/g, '');
  const pr = pending.find((r) => hay.includes(normalize(r.code).replace(/[^a-z0-9]/g, '')));
  if (!pr) return;
  const paid = (pr.paid_amount || 0) + t.amount;
  const done = paid >= pr.amount;
  await run(env, `UPDATE payment_requests SET paid_amount=?, status=?, paid_txn_id=?, paid_at=? WHERE id=?`,
    paid, done ? 'paid' : 'pending', txnId, done ? new Date().toISOString().replace('T', ' ').slice(0, 19) : null, pr.id);
  const tagUpd = pr.customer ? `KH: ${pr.customer}` : null;
  await run(env, `UPDATE transactions SET category_id=COALESCE(?, category_id), categorized_by=CASE WHEN ? IS NOT NULL THEN 'rule' ELSE categorized_by END,
    tag=COALESCE(tag, ?), note=COALESCE(note, ?) WHERE id=?`, pr.category_id, pr.category_id, tagUpd, `Thu theo mã ${pr.code}`, txnId);
}

async function createPaymentRequest(env, b, user) {
  const amount = Math.round(Number(b.amount));
  if (!(amount > 0)) throw new HttpError(400, 'Số tiền không hợp lệ');
  const s = await getSettings(env);
  const prefix = (s.payment_prefix || 'TT').toUpperCase();
  let code = b.code ? String(b.code).toUpperCase().replace(/[^A-Z0-9]/g, '') : null;
  for (let i = 0; !code && i < 5; i++) {
    const c = prefix + String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
    if (!(await first(env, 'SELECT 1 FROM payment_requests WHERE code=?', c))) code = c;
  }
  await run(env, `INSERT INTO payment_requests (code, amount, customer, description, account_number, bank, category_id, created_by) VALUES (?,?,?,?,?,?,?,?)`,
    code, amount, b.customer || null, b.description || null, b.account_number || s.qr_account || null, b.bank || s.qr_bank || null,
    b.category_id || null, user.username);
  return json(await first(env, 'SELECT * FROM payment_requests WHERE code=?', code));
}

// ---------------------------------------------------------------- đối soát SePay API v2
export async function syncFromSepay(env) {
  const c = await cfg(env);
  if (!c.apiToken) return { skipped: 'Chưa nhập API Token SePay ở tab Thiết lập SePay' };
  const base = env.SEPAY_API_BASE || SEPAY_BASE[c.sepayEnv] || SEPAY_BASE.sandbox;
  const log = await run(env, `INSERT INTO sync_log (started_at) VALUES (datetime('now'))`);
  const logId = log.meta.last_row_id;
  let fetched = 0, inserted = 0;
  try {
    // Tài khoản ngân hàng + số dư
    for (let page = 1; page <= 10; page++) {
      const r = await sepayGet(env, base, '/bank-accounts', { page, per_page: 100 });
      for (const a of r.data || []) {
        await run(env, `INSERT INTO bank_accounts (account_number, sepay_id, bank, holder, label, balance, last_transaction, synced_at)
          VALUES (?,?,?,?,?,?,?,datetime('now')) ON CONFLICT(account_number) DO UPDATE SET sepay_id=excluded.sepay_id, bank=excluded.bank,
          holder=excluded.holder, label=excluded.label, balance=excluded.balance, last_transaction=excluded.last_transaction, synced_at=excluded.synced_at`,
          a.account_number, a.id, a.bank_short_name, a.account_holder_name, a.label, a.accumulated, a.last_transaction);
      }
      if (!r.meta?.pagination?.has_more) break;
    }
    // Giao dịch trong N giờ gần nhất
    const hours = Number(env.SYNC_LOOKBACK_HOURS || 48);
    const from = vnNow(-hours * 3600 * 1000);
    for (let page = 1; page <= 200; page++) {
      const r = await sepayGet(env, base, '/transactions', { transaction_date_from: from, transaction_date_sort: 'asc', per_page: 100, page });
      for (const x of r.data || []) {
        fetched++;
        const type = x.transfer_type === 'out' || (x.amount_out > 0 && !x.amount_in) ? 'out' : 'in';
        const res = await ingestTransaction(env, {
          source: 'api',
          sepay_uuid: x.id,
          reference_code: x.reference_number || null,
          account_number: x.account_number || null,
          bank: x.bank_brand_name || null,
          txn_date: x.transaction_date,
          type,
          amount: type === 'in' ? Number(x.amount_in) : Number(x.amount_out),
          content: x.transaction_content || '',
          code: x.code || null,
          sub_account: x.va || null,
          accumulated: x.accumulated ? Number(x.accumulated) : null,
        });
        if (!res.duplicate) inserted++;
      }
      if (!r.meta?.pagination?.has_more) break;
    }
    await run(env, `UPDATE sync_log SET finished_at=datetime('now'), fetched=?, inserted=? WHERE id=?`, fetched, inserted, logId);
    return { fetched, inserted };
  } catch (e) {
    await run(env, `UPDATE sync_log SET finished_at=datetime('now'), fetched=?, inserted=?, error=? WHERE id=?`, fetched, inserted, String(e.message || e), logId);
    throw e;
  }
}

async function sepayGet(env, base, path, params) {
  const u = new URL(base + path);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, String(v));
  for (let attempt = 0; attempt < 5; attempt++) {
    const r = await fetch(u, { headers: { Authorization: `Bearer ${(await cfg(env)).apiToken}`, 'Content-Type': 'application/json' } });
    if (r.status === 429) {
      const wait = Number(r.headers.get('retry-after') || 1);
      await sleep(Math.min(wait, 10) * 1000);
      continue;
    }
    if (!r.ok) throw new Error(`SePay ${path} HTTP ${r.status}: ${(await r.text()).slice(0, 200)}`);
    await sleep(350); // giới hạn 3 request/giây
    return r.json();
  }
  throw new Error('SePay rate limit liên tục');
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- giao dịch
function txnFilters(url) {
  const q = url.searchParams;
  const where = [];
  const args = [];
  if (q.get('from')) { where.push('t.txn_date >= ?'); args.push(q.get('from') + ' 00:00:00'); }
  if (q.get('to')) { where.push('t.txn_date <= ?'); args.push(q.get('to') + ' 23:59:59'); }
  if (q.get('type')) { where.push('t.type = ?'); args.push(q.get('type')); }
  if (q.get('account')) { where.push('t.account_number = ?'); args.push(q.get('account')); }
  if (q.get('category') === 'none') where.push('t.category_id IS NULL');
  else if (q.get('category')) { where.push('t.category_id = ?'); args.push(Number(q.get('category'))); }
  if (q.get('tag')) { where.push('t.tag LIKE ?'); args.push('%' + q.get('tag') + '%'); }
  if (q.get('source')) { where.push('t.source = ?'); args.push(q.get('source')); }
  if (q.get('q')) {
    where.push('(t.content LIKE ? OR t.description LIKE ? OR t.code LIKE ? OR t.reference_code LIKE ? OR t.note LIKE ? OR t.tag LIKE ?)');
    const s = '%' + q.get('q') + '%';
    args.push(s, s, s, s, s, s);
  }
  return { sql: where.length ? 'WHERE ' + where.join(' AND ') : '', args };
}

async function listTransactions(env, url) {
  const { sql, args } = txnFilters(url);
  const page = Math.max(1, Number(url.searchParams.get('page') || 1));
  const per = Math.min(200, Math.max(1, Number(url.searchParams.get('per_page') || 50)));
  const total = await first(env, `SELECT COUNT(*) n, IFNULL(SUM(CASE WHEN type='in' THEN amount END),0) tin, IFNULL(SUM(CASE WHEN type='out' THEN amount END),0) tout FROM transactions t ${sql}`, ...args);
  const rows = await all(env, `SELECT t.*, c.name category_name, c.color category_color FROM transactions t LEFT JOIN categories c ON c.id=t.category_id
    ${sql} ORDER BY t.txn_date DESC, t.id DESC LIMIT ? OFFSET ?`, ...args, per, (page - 1) * per);
  return json({ data: rows, total: total.n, sum_in: total.tin, sum_out: total.tout, page, per_page: per });
}

async function createManual(env, b, user) {
  const amount = Math.round(Number(b.amount));
  if (!(amount > 0)) throw new HttpError(400, 'Số tiền không hợp lệ');
  if (!['in', 'out'].includes(b.type)) throw new HttpError(400, 'Loại phải là in hoặc out');
  const date = /^\d{4}-\d{2}-\d{2}/.test(b.txn_date || '') ? String(b.txn_date).replace('T', ' ').padEnd(19, ':00').slice(0, 19) : vnNow();
  const r = await ingestTransaction(env, {
    source: 'manual', txn_date: date, type: b.type, amount, content: b.content || '', account_number: b.account_number || 'TIEN_MAT',
    bank: b.account_number ? null : 'Tiền mặt', category_id: b.category_id || null, tag: b.tag || null, note: b.note || null, created_by: user.username,
  });
  return json(r);
}

async function updateTransaction(env, id, b, user) {
  const t = await first(env, 'SELECT * FROM transactions WHERE id=?', id);
  if (!t) throw new HttpError(404, 'Không có giao dịch');
  const sets = [];
  const args = [];
  if ('category_id' in b) { sets.push('category_id=?', "categorized_by='user'"); args.push(b.category_id || null); }
  if ('tag' in b) { sets.push('tag=?'); args.push(b.tag || null); }
  if ('note' in b) { sets.push('note=?'); args.push(b.note || null); }
  if (t.source === 'manual') {
    if ('amount' in b) { sets.push('amount=?'); args.push(Math.round(Number(b.amount))); }
    if ('content' in b) { sets.push('content=?'); args.push(b.content || ''); }
    if ('type' in b && ['in', 'out'].includes(b.type)) { sets.push('type=?'); args.push(b.type); }
    if ('txn_date' in b) { sets.push('txn_date=?'); args.push(String(b.txn_date).replace('T', ' ').padEnd(19, ':00').slice(0, 19)); }
  }
  if (!sets.length) return json({ ok: true });
  sets.push("updated_at=datetime('now')");
  await run(env, `UPDATE transactions SET ${sets.join(', ')} WHERE id=?`, ...args, id);
  return json({ ok: true });
}

async function deleteTransaction(env, id) {
  const t = await first(env, 'SELECT source FROM transactions WHERE id=?', id);
  if (!t) throw new HttpError(404, 'Không có giao dịch');
  if (t.source !== 'manual') throw new HttpError(400, 'Chỉ xoá được giao dịch nhập tay. Giao dịch ngân hàng giữ nguyên để đối soát.');
  await run(env, 'DELETE FROM transactions WHERE id=?', id);
  return json({ ok: true });
}

async function exportCsv(env, url) {
  const { sql, args } = txnFilters(url);
  const rows = await all(env, `SELECT t.*, c.name category_name FROM transactions t LEFT JOIN categories c ON c.id=t.category_id ${sql} ORDER BY t.txn_date, t.id`, ...args);
  const head = ['Ngày giờ', 'Loại', 'Số tiền', 'Thu', 'Chi', 'Danh mục', 'Tag', 'Nội dung', 'Ghi chú', 'Tài khoản', 'Ngân hàng', 'Mã TT', 'Mã tham chiếu', 'Số dư sau GD', 'Nguồn'];
  const esc = (v) => { const s = v == null ? '' : String(v); return /[",\n;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  const lines = [head.join(',')];
  for (const t of rows) {
    lines.push([t.txn_date, t.type === 'in' ? 'Thu' : 'Chi', t.amount, t.type === 'in' ? t.amount : '', t.type === 'out' ? t.amount : '', t.category_name,
      t.tag, t.content, t.note, t.account_number, t.bank, t.code, t.reference_code, t.accumulated, t.source].map(esc).join(','));
  }
  return new Response('﻿' + lines.join('\r\n'), {
    headers: { 'content-type': 'text/csv; charset=utf-8', 'content-disposition': `attachment; filename="thu-chi-${vnNow().slice(0, 10)}.csv"` },
  });
}

// ---------------------------------------------------------------- tổng quan
async function summary(env, url) {
  const { sql, args } = txnFilters(url);
  const totals = await first(env, `SELECT IFNULL(SUM(CASE WHEN type='in' THEN amount END),0) tin, IFNULL(SUM(CASE WHEN type='out' THEN amount END),0) tout,
    COUNT(*) n, SUM(CASE WHEN category_id IS NULL THEN 1 ELSE 0 END) uncategorized FROM transactions t ${sql}`, ...args);
  const byMonth = await all(env, `SELECT substr(txn_date,1,7) month, IFNULL(SUM(CASE WHEN type='in' THEN amount END),0) tin,
    IFNULL(SUM(CASE WHEN type='out' THEN amount END),0) tout FROM transactions t ${sql} GROUP BY month ORDER BY month`, ...args);
  const byCategory = await all(env, `SELECT t.type, t.category_id, IFNULL(c.name,'Chưa phân loại') name, IFNULL(c.color,'#94a3b8') color, SUM(t.amount) total, COUNT(*) n
    FROM transactions t LEFT JOIN categories c ON c.id=t.category_id ${sql} GROUP BY t.type, t.category_id ORDER BY total DESC`, ...args);
  const byAccount = await all(env, `SELECT t.account_number, MAX(t.bank) bank, IFNULL(SUM(CASE WHEN type='in' THEN amount END),0) tin,
    IFNULL(SUM(CASE WHEN type='out' THEN amount END),0) tout FROM transactions t ${sql} GROUP BY t.account_number ORDER BY tin DESC`, ...args);
  const accounts = await all(env, 'SELECT * FROM bank_accounts ORDER BY bank');
  const pending = await first(env, "SELECT COUNT(*) n, IFNULL(SUM(amount - paid_amount),0) total FROM payment_requests WHERE status='pending'");
  const lastSync = await first(env, 'SELECT * FROM sync_log ORDER BY id DESC LIMIT 1');
  return json({ totals, byMonth, byCategory, byAccount, accounts, pending, lastSync });
}

// ---------------------------------------------------------------- danh mục, quy tắc, cài đặt
async function saveCategory(env, b) {
  if (!b.name || !['in', 'out'].includes(b.type)) throw new HttpError(400, 'Cần tên và loại (in/out)');
  if (b.id) await run(env, 'UPDATE categories SET name=?, type=?, color=?, sort=? WHERE id=?', b.name, b.type, b.color || '#64748b', b.sort || 0, b.id);
  else await run(env, 'INSERT INTO categories (name, type, color, sort) VALUES (?,?,?,?)', b.name, b.type, b.color || '#64748b', b.sort || 0);
  return json({ ok: true });
}
async function saveRule(env, b) {
  if (!b.pattern) throw new HttpError(400, 'Cần từ khoá');
  if (b.match_type === 'regex') { try { new RegExp(b.pattern); } catch { throw new HttpError(400, 'Regex không hợp lệ'); } }
  const vals = [b.pattern, b.match_type === 'regex' ? 'regex' : 'contains', ['in', 'out'].includes(b.transfer_type) ? b.transfer_type : 'any',
    b.category_id || null, b.tag || null, Number(b.priority ?? 100), b.active === 0 || b.active === false ? 0 : 1];
  if (b.id) await run(env, 'UPDATE rules SET pattern=?, match_type=?, transfer_type=?, category_id=?, tag=?, priority=?, active=? WHERE id=?', ...vals, b.id);
  else await run(env, 'INSERT INTO rules (pattern, match_type, transfer_type, category_id, tag, priority, active) VALUES (?,?,?,?,?,?,?)', ...vals);
  return json({ ok: true });
}
const SETTING_KEYS = ['qr_account', 'qr_bank', 'qr_holder', 'qr_store', 'payment_prefix', 'company_name'];
async function getSettings(env) {
  const rows = await all(env, 'SELECT key, value FROM settings');
  // Chỉ trả cài đặt hiển thị, không bao giờ trả token / secret
  return Object.fromEntries(rows.filter((r) => SETTING_KEYS.includes(r.key)).map((r) => [r.key, r.value]));
}
async function saveSettings(env, b) {
  const stmts = SETTING_KEYS.filter((k) => k in b).map((k) =>
    env.DB.prepare('INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').bind(k, String(b[k] ?? '')));
  if (stmts.length) await env.DB.batch(stmts);
  return json(await getSettings(env));
}

// ---------------------------------------------------------------- thiết lập SePay
const mask = (v) => (v ? '••••' + String(v).slice(-4) : '');
async function sepayConfigView(env, url) {
  const c = await cfg(env);
  return {
    sepay_env: c.sepayEnv,
    webhook_auth: c.webhookAuth,
    api_token_set: !!c.apiToken,
    api_token_hint: mask(c.apiToken),
    webhook_secret_set: !!c.webhookSecret,
    webhook_secret_hint: mask(c.webhookSecret),
    webhook_url: `${url.origin}/api/sepay/webhook`,
    api_base: env.SEPAY_API_BASE || SEPAY_BASE[c.sepayEnv] || SEPAY_BASE.sandbox,
    last_webhook: await first(env, "SELECT txn_date, amount, type, created_at FROM transactions WHERE source='webhook' ORDER BY id DESC LIMIT 1"),
  };
}
async function saveSepayConfig(env, b, url) {
  const stmts = [];
  const put = (k, v) => stmts.push(env.DB.prepare('INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').bind(k, v));
  if (b.sepay_env) { if (!['sandbox', 'production'].includes(b.sepay_env)) throw new HttpError(400, 'Môi trường không hợp lệ'); put('sepay_env', b.sepay_env); }
  if (b.webhook_auth) { if (!['hmac', 'apikey', 'none'].includes(b.webhook_auth)) throw new HttpError(400, 'Kiểu xác thực không hợp lệ'); put('webhook_auth', b.webhook_auth); }
  if (b.api_token) {
    const t = String(b.api_token).trim();
    if (!/^[A-Za-z0-9]{20,128}$/.test(t)) throw new HttpError(400, 'API Token không đúng định dạng (chuỗi chữ và số, thường 64 ký tự)');
    put('sepay_api_token', t);
  }
  if (b.webhook_secret) {
    const w = String(b.webhook_secret).trim();
    if (w.length < 16) throw new HttpError(400, 'Secret Key nên dài ít nhất 16 ký tự');
    put('sepay_webhook_secret', w);
  }
  if (stmts.length) await env.DB.batch(stmts);
  env._cfg = null;
  return json(await sepayConfigView(env, url));
}
async function testSepay(env) {
  const c = await cfg(env);
  if (!c.apiToken) return { ok: false, message: 'Chưa nhập API Token' };
  const base = env.SEPAY_API_BASE || SEPAY_BASE[c.sepayEnv] || SEPAY_BASE.sandbox;
  const r = await fetch(`${base}/bank-accounts?per_page=100`, { headers: { Authorization: `Bearer ${c.apiToken}` } });
  if (r.status === 401) return { ok: false, message: `Token bị từ chối (401). Kiểm tra token có đúng môi trường ${c.sepayEnv === 'sandbox' ? 'Test mode' : 'Production'} không.` };
  if (!r.ok) return { ok: false, message: `SePay trả HTTP ${r.status}` };
  const d = await r.json();
  return { ok: true, accounts: (d.data || []).map((a) => ({ bank: a.bank_short_name, account_number: a.account_number, holder: a.account_holder_name, balance: a.accumulated })) };
}

// ---------------------------------------------------------------- người dùng & phiên
async function login(request, env) {
  const b = await body(request);
  await ensureAdmin(env);
  const u = await first(env, 'SELECT * FROM users WHERE username=? AND active=1', String(b.username || '').trim().toLowerCase());
  if (!u || !(await verifyPassword(String(b.password || ''), u.password_hash))) {
    await sleep(500);
    throw new HttpError(401, 'Sai tên đăng nhập hoặc mật khẩu');
  }
  const token = await signSession(env, { uid: u.id, exp: Date.now() + SESSION_HOURS * 3600e3 });
  return json({ ok: true }, 200, { 'set-cookie': `sid=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_HOURS * 3600}` });
}

async function ensureAdmin(env) {
  const c = await first(env, 'SELECT COUNT(*) n FROM users');
  if (c.n > 0) return;
  if (!env.ADMIN_PASSWORD) throw new HttpError(500, 'Chưa đặt ADMIN_PASSWORD để tạo tài khoản admin đầu tiên');
  await run(env, "INSERT INTO users (username, display_name, password_hash, role) VALUES ('admin','Quản trị',?, 'admin')", await hashPassword(env.ADMIN_PASSWORD));
}

async function currentUser(request, env) {
  const cookie = request.headers.get('cookie') || '';
  const sid = cookie.split(/;\s*/).find((c) => c.startsWith('sid='))?.slice(4);
  if (!sid) return null;
  const s = await verifySession(env, sid);
  if (!s || s.exp < Date.now()) return null;
  return first(env, 'SELECT id, username, display_name, role FROM users WHERE id=? AND active=1', s.uid);
}

async function saveUser(env, b) {
  const role = ROLE_LEVEL[b.role] ? b.role : 'viewer';
  if (b.id) {
    await run(env, 'UPDATE users SET display_name=?, role=?, active=? WHERE id=?', b.display_name || null, role, b.active === 0 || b.active === false ? 0 : 1, b.id);
    if (b.password) await run(env, 'UPDATE users SET password_hash=? WHERE id=?', await hashPassword(b.password), b.id);
  } else {
    const username = String(b.username || '').trim().toLowerCase();
    if (!/^[a-z0-9._-]{3,32}$/.test(username)) throw new HttpError(400, 'Tên đăng nhập 3-32 ký tự a-z, 0-9, . _ -');
    if (!b.password || b.password.length < 8) throw new HttpError(400, 'Mật khẩu tối thiểu 8 ký tự');
    await run(env, 'INSERT INTO users (username, display_name, password_hash, role) VALUES (?,?,?,?)', username, b.display_name || null, await hashPassword(b.password), role);
  }
  return json({ ok: true });
}
async function changePassword(env, user, b) {
  const u = await first(env, 'SELECT password_hash FROM users WHERE id=?', user.id);
  if (!(await verifyPassword(String(b.old_password || ''), u.password_hash))) throw new HttpError(400, 'Mật khẩu cũ không đúng');
  if (!b.new_password || b.new_password.length < 8) throw new HttpError(400, 'Mật khẩu mới tối thiểu 8 ký tự');
  await run(env, 'UPDATE users SET password_hash=? WHERE id=?', await hashPassword(b.new_password), user.id);
  return json({ ok: true });
}

// ---------------------------------------------------------------- crypto helpers
const enc = new TextEncoder();
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const b64u = (s) => btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = (s) => atob(s.replace(/-/g, '+').replace(/_/g, '/'));

export async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}
function timingSafeEqual(a, b) {
  a = String(a); b = String(b);
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}
async function signSession(env, payload) {
  const { sessionSecret } = await cfg(env);
  const data = b64u(JSON.stringify(payload));
  return `${data}.${await hmacHex(sessionSecret, data)}`;
}
async function verifySession(env, token) {
  const [data, sig] = token.split('.');
  if (!data || !sig) return null;
  const { sessionSecret } = await cfg(env);
  if (!timingSafeEqual(await hmacHex(sessionSecret, data), sig)) return null;
  try { return JSON.parse(unb64u(data)); } catch { return null; }
}
async function pbkdf2(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return toHex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256));
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const it = 100000;
  return `pbkdf2$${it}$${toHex(salt)}$${await pbkdf2(password, salt, it)}`;
}
async function verifyPassword(password, stored) {
  const [, it, saltHex, hash] = String(stored).split('$');
  const salt = new Uint8Array(saltHex.match(/../g).map((h) => parseInt(h, 16)));
  return timingSafeEqual(await pbkdf2(password, salt, Number(it)), hash);
}

// Giờ Việt Nam dạng 'YYYY-MM-DD HH:mm:ss'
export function vnNow(offsetMs = 0) {
  return new Date(Date.now() + offsetMs + 7 * 3600e3).toISOString().replace('T', ' ').slice(0, 19);
}
