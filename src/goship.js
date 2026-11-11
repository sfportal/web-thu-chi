// Tích hợp Goship (https://doc.goship.io): nhiều tài khoản, tra cước, tạo/huỷ vận đơn, nhận webhook trạng thái
import { HttpError, json, all, first, run, enc, toHex, mask, timingSafeEqual } from './lib.js';

export const GOSHIP_BASE = {
  production: 'https://api.goship.io/api/v2',
  sandbox: 'https://sandbox.goship.io/api/v2',
};
export const GS_STATUS = {
  900: 'Đơn mới', 901: 'Chờ lấy hàng', 902: 'Lấy hàng', 903: 'Đã lấy hàng', 904: 'Giao hàng', 905: 'Giao thành công',
  906: 'Giao thất bại', 907: 'Đang chuyển hoàn', 908: 'Chuyển hoàn', 909: 'Đã đối soát', 910: 'Đã đối soát khách',
  911: 'Đã trả COD cho khách', 912: 'Chờ thanh toán COD', 913: 'Hoàn thành', 914: 'Đơn hủy', 915: 'Chậm lấy/giao',
  916: 'Giao hàng một phần', 917: 'Thất lạc hàng', 918: 'Đang lưu kho', 919: 'Đang vận chuyển', 1000: 'Đơn lỗi',
};
const base = (env, a) => env.GOSHIP_API_BASE || GOSHIP_BASE[a.env] || GOSHIP_BASE.production;
const envName = (a) => (a.env === 'sandbox' ? 'Sandbox' : 'Production');

// ---------------------------------------------------------------- gọi Goship API
export async function gsFetch(env, a, method, path, payload) {
  if (!a.access_token) throw new HttpError(400, `Tài khoản Goship "${a.name}" chưa có Access Token`);
  let r;
  try {
    r = await fetch(base(env, a) + path, {
      method,
      headers: { Accept: 'application/json', 'Content-Type': 'application/json', Authorization: 'Bearer ' + a.access_token },
      body: payload ? JSON.stringify(payload) : undefined,
    });
  } catch (e) {
    throw new HttpError(502, 'Không gọi được Goship: ' + (e.message || e));
  }
  const text = await r.text();
  let d;
  try { d = JSON.parse(text); } catch { d = { message: text.slice(0, 200) }; }
  if (r.status === 401 || d.code === 401)
    throw new HttpError(502, `Goship từ chối Access Token của "${a.name}" (401). Kiểm tra token có đúng môi trường ${envName(a)} không.`);
  if (r.status === 429) throw new HttpError(429, 'Goship báo vượt giới hạn 300 request/phút, thử lại sau ít phút');
  if (!r.ok || String(d.status || '').toLowerCase() === 'error') {
    const st = r.status === 422 || d.code === 422 ? 422 : r.status === 404 || d.code === 404 ? 404 : 502;
    throw new HttpError(st, 'Goship: ' + gsErrMsg(d, r.status));
  }
  return d;
}
export function gsErrMsg(d, st) {
  const e = d?.data?.errors;
  if (e && typeof e === 'object') return Object.values(e).flat().join('; ');
  return d?.message || d?.data?.error || (typeof d?.data === 'string' ? d.data : '') || 'HTTP ' + st;
}

// ---------------------------------------------------------------- tài khoản
export const getGsAccount = (env, id) => first(env, 'SELECT * FROM goship_accounts WHERE id=?', Number(id));
const parseSender = (a) => { try { return a.sender ? JSON.parse(a.sender) : {}; } catch { return {}; } };

// Chọn tài khoản theo id hoặc lấy tài khoản hoạt động đầu tiên; allowed = danh sách id được phép (null = tất cả)
export async function pickAccount(env, id, allowed = null) {
  if (id !== undefined && id !== null && id !== '') {
    if (allowed && !allowed.includes(String(id))) throw new HttpError(403, 'Không được dùng tài khoản Goship này');
    const a = await getGsAccount(env, id);
    if (!a || !a.active) throw new HttpError(404, 'Không có tài khoản Goship đang hoạt động với id ' + id);
    return a;
  }
  const list = await all(env, 'SELECT * FROM goship_accounts WHERE active=1 ORDER BY id');
  const a = list.find((x) => !allowed || allowed.includes(String(x.id)));
  if (!a) throw new HttpError(400, 'Chưa có tài khoản Goship nào hoạt động');
  return a;
}

export async function gsAccountsView(env, url, full = true) {
  const rows = await all(env, `SELECT a.*, (SELECT COUNT(*) FROM goship_shipments s WHERE s.account_id=a.id) shipments FROM goship_accounts a ORDER BY a.id`);
  const out = [];
  for (const a of rows) {
    const v = { id: a.id, name: a.name, env: a.env, active: a.active, sender: parseSender(a), shipments: a.shipments, access_token_set: !!a.access_token };
    if (full) {
      Object.assign(v, {
        access_token_hint: mask(a.access_token), client_secret_set: !!a.client_secret, client_secret_hint: mask(a.client_secret),
        webhook_url: `${url.origin}/api/goship/webhook/${a.id}/${a.webhook_token}`,
        last_check_at: a.last_check_at, last_error: a.last_error,
        last_webhook: await first(env, 'SELECT received_at, status, message FROM goship_webhook_log WHERE account_id=? ORDER BY id DESC LIMIT 1', a.id),
      });
    }
    out.push(v);
  }
  return out;
}

const SENDER_KEYS = ['name', 'phone', 'street', 'city', 'district', 'ward'];
export async function saveGsAccount(env, b, url) {
  const fields = [], args = [];
  const set = (f, v) => { fields.push(f + '=?'); args.push(v); };
  if (b.name !== undefined) { if (!String(b.name).trim()) throw new HttpError(400, 'Cần đặt tên tài khoản Goship'); set('name', String(b.name).trim()); }
  if (b.env !== undefined) { if (!['sandbox', 'production'].includes(b.env)) throw new HttpError(400, 'Môi trường không hợp lệ'); set('env', b.env); }
  if (b.access_token) {
    const t = String(b.access_token).trim().replace(/^Bearer\s+/i, '');
    if (t.length < 20 || /\s/.test(t)) throw new HttpError(400, 'Access Token không đúng định dạng (chuỗi dài, thường bắt đầu bằng eyJ)');
    set('access_token', t);
  }
  if (b.client_secret) set('client_secret', String(b.client_secret).trim());
  if (b.clear_client_secret) set('client_secret', null);
  if (b.sender !== undefined) {
    const s = {};
    for (const k of SENDER_KEYS) if (b.sender?.[k] != null && String(b.sender[k]).trim()) s[k] = String(b.sender[k]).trim();
    set('sender', JSON.stringify(s));
  }
  if (b.active !== undefined) set('active', b.active ? 1 : 0);
  if (b.rotate_webhook) set('webhook_token', newToken());
  if (b.id) {
    if (!(await getGsAccount(env, b.id))) throw new HttpError(404, 'Không có tài khoản Goship');
    if (fields.length) await run(env, `UPDATE goship_accounts SET ${fields.join(', ')} WHERE id=?`, ...args, b.id);
  } else {
    if (!b.name) throw new HttpError(400, 'Cần đặt tên tài khoản Goship');
    if (!fields.some((f) => f.startsWith('webhook_token'))) set('webhook_token', newToken());
    const cols = fields.map((f) => f.split('=')[0]);
    await run(env, `INSERT INTO goship_accounts (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`, ...args);
  }
  return json(await gsAccountsView(env, url));
}
const newToken = () => toHex(crypto.getRandomValues(new Uint8Array(16)));

export async function testGsAccount(env, id) {
  const a = await getGsAccount(env, id);
  if (!a) return { ok: false, message: 'Không có tài khoản Goship' };
  try {
    const d = await gsFetch(env, a, 'GET', '/cities');
    await run(env, "UPDATE goship_accounts SET last_check_at=datetime('now'), last_error=NULL WHERE id=?", a.id);
    return { ok: true, message: `Kết nối ${envName(a)} thành công, đọc được ${(d.data || []).length} tỉnh/thành.` };
  } catch (e) {
    await run(env, "UPDATE goship_accounts SET last_check_at=datetime('now'), last_error=? WHERE id=?", e.message, a.id);
    return { ok: false, message: e.message };
  }
}

// Đăng ký URL webhook của tài khoản lên Goship (POST /webhooks), bỏ qua nếu đã có
export async function registerGsWebhook(env, id, url) {
  const a = await getGsAccount(env, id);
  if (!a) throw new HttpError(404, 'Không có tài khoản Goship');
  const endpoint = `${url.origin}/api/goship/webhook/${a.id}/${a.webhook_token}`;
  const list = (await gsFetch(env, a, 'GET', '/webhooks')).data || [];
  if (list.some((w) => w.endpoint === endpoint)) return { ok: true, message: 'Webhook đã được đăng ký trên Goship từ trước', webhooks: list };
  await gsFetch(env, a, 'POST', '/webhooks', { endpoint });
  const after = (await gsFetch(env, a, 'GET', '/webhooks')).data || [];
  return { ok: true, message: a.env === 'sandbox' ? 'Đã đăng ký. Lưu ý: Sandbox của Goship không bắn webhook thật.' : 'Đã đăng ký webhook trên Goship', webhooks: after };
}

// ---------------------------------------------------------------- địa giới (có cache 1 ngày)
export async function gsLocations(env, a, kind, code) {
  let path;
  if (kind === 'cities') path = '/cities';
  else {
    if (!/^\d+$/.test(String(code || ''))) throw new HttpError(400, 'Mã tỉnh/quận không hợp lệ');
    path = kind === 'districts' ? `/cities/${code}/districts` : kind === 'wards' ? `/districts/${code}/wards` : null;
  }
  if (!path) throw new HttpError(404, 'Không có loại địa giới này');
  const cache = typeof caches !== 'undefined' ? caches.default : null;
  const key = new Request(`https://goship-cache.local/${a.env}${path}`);
  const hit = cache && (await cache.match(key));
  if (hit) return hit.json();
  const d = await gsFetch(env, a, 'GET', path);
  let data = d.data || [];
  const pages = Math.min(10, d.meta?.pagination?.total_pages || 1);
  for (let pg = 2; pg <= pages; pg++) data = data.concat((await gsFetch(env, a, 'GET', `${path}?page=${pg}`)).data || []);
  data = data.map((x) => ({ id: String(x.id), name: x.name }));
  if (cache && data.length) await cache.put(key, new Response(JSON.stringify(data), { headers: { 'content-type': 'application/json', 'cache-control': 'max-age=86400' } }));
  return data;
}

// ---------------------------------------------------------------- tra cước & tạo vận đơn
const str = (v) => (v === undefined || v === null ? '' : String(v).trim());
function address(a, x, withContact) {
  const s = { ...parseSender(a) };
  const src = x || {};
  const out = {};
  const pick = (k) => str(src[k]) || (withContact === 'from' ? str(s[k]) : '');
  for (const k of ['city', 'district', 'ward']) { const v = pick(k); if (v) out[k] = v; }
  if (withContact) for (const k of ['name', 'phone', 'street']) { const v = pick(k); if (v) out[k] = v; }
  return out;
}
function requireAddr(o, label, contact) {
  const miss = [];
  if (!o.city) miss.push('city');
  if (!o.district) miss.push('district');
  if (contact) for (const k of ['name', 'phone', 'street']) if (!o[k]) miss.push(k);
  if (miss.length) throw new HttpError(422, `Thiếu thông tin ${label}: ${miss.join(', ')}`);
}
export function parcel(p) {
  p = p || {};
  const n = (v, d) => (v === undefined || v === null || v === '' ? d : Number(v));
  const out = { cod: n(p.cod, 0), amount: n(p.amount, 0), weight: n(p.weight), width: n(p.width, 10), height: n(p.height, 10), length: n(p.length, 10) };
  for (const [k, v] of Object.entries(out)) if (!Number.isFinite(v) || v < 0) throw new HttpError(422, `parcel.${k} phải là số không âm`);
  if (!out.weight) throw new HttpError(422, 'Cần parcel.weight (gram) lớn hơn 0');
  if (p.metadata) out.metadata = String(p.metadata).slice(0, 500);
  if (p.name) out.name = String(p.name).slice(0, 200);
  return out;
}

export async function gsRates(env, a, b) {
  const from = address(a, b.address_from, 'from'), to = address(a, b.address_to, null);
  requireAddr(from, 'địa chỉ gửi (address_from)'); requireAddr(to, 'địa chỉ nhận (address_to)');
  const pc = parcel(b.parcel);
  const d = await gsFetch(env, a, 'POST', '/rates', { shipment: { address_from: pickLoc(from), address_to: pickLoc(to), parcel: { cod: pc.cod, amount: pc.amount, weight: pc.weight, width: pc.width, height: pc.height, length: pc.length } } });
  return (d.data || []).map((r) => ({
    rate: r.rate || r.id, carrier_name: r.carrier_name, carrier_short_name: r.carrier_short_name, carrier_logo: r.carrier_logo,
    service: r.service, expected: r.expected, total_fee: num(r.total_fee), total_amount: num(r.total_amount), cod_fee: num(r.cod_fee),
    insurance_fee: num(r.insurance_fee), return_fee: num(r.return_fee), own_account: r.own_account ? 1 : 0, report: r.report || null,
  })).sort((x, y) => x.total_fee - y.total_fee);
}
const pickLoc = (o) => { const r = { city: o.city, district: o.district }; if (o.ward) r.ward = o.ward; return r; };
const num = (v) => (v === undefined || v === null || v === '' ? null : Number(v));

export async function gsCreateShipment(env, a, b, source, apiKeyId = null) {
  const rate = str(b.rate);
  if (!rate) throw new HttpError(422, 'Cần rate (lấy từ bước tra cước)');
  const from = address(a, b.address_from, 'from'), to = address(a, b.address_to, 'to');
  requireAddr(from, 'người gửi (address_from)', true); requireAddr(to, 'người nhận (address_to)', true);
  const pc = parcel(b.parcel);
  const payer = b.payer === undefined || b.payer === null || b.payer === '' ? 1 : Number(b.payer);
  if (![0, 1].includes(payer)) throw new HttpError(422, 'payer chỉ nhận 0 (người nhận trả) hoặc 1 (shop trả)');
  const orderId = str(b.order_id).slice(0, 64) || null;
  if (orderId) {
    const dup = await first(env, 'SELECT * FROM goship_shipments WHERE account_id=? AND order_id=? AND COALESCE(status,0)!=914', a.id, orderId);
    if (dup) return { ...dup, duplicate: true };
  }
  const shipment = { rate, payer, address_from: from, address_to: to, parcel: pc };
  if (orderId) shipment.order_id = orderId;
  const d = await gsFetch(env, a, 'POST', '/shipments', { shipment });
  if (!d.id) throw new HttpError(502, 'Goship không trả mã vận đơn' + (d.carrier_error ? ': ' + JSON.stringify(d.carrier_error) : ''));
  const status = num(d.shipment_status) ?? 900;
  await run(env, `INSERT INTO goship_shipments (account_id, gcode, order_id, carrier_code, carrier, carrier_short_name, service, payer, cod, fee, amount_return_shop,
      weight, status, status_text, sorting_code, to_name, to_phone, to_address, carrier_error, source, api_key_id)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(gcode) DO NOTHING`,
    a.id, d.id, orderId, d.tracking_number || null, d.carrier || null, d.carrier_short_name || null, str(b.service) || null, payer,
    num(d.cod) ?? pc.cod, num(d.fee), num(d.amount_return_shop), pc.weight, status, d.shipment_status_txt || GS_STATUS[status] || null,
    d.sorting_code || null, to.name, to.phone, [to.street, to.ward, to.district, to.city].filter(Boolean).join(', '),
    d.carrier_error ? JSON.stringify(d.carrier_error).slice(0, 1000) : null, source, apiKeyId);
  return first(env, 'SELECT * FROM goship_shipments WHERE gcode=?', d.id);
}

// Lấy lại thông tin vận đơn từ Goship và cập nhật bản lưu
export async function gsRefresh(env, s) {
  const a = await getGsAccount(env, s.account_id);
  if (!a) throw new HttpError(404, 'Tài khoản Goship của vận đơn không còn');
  const d = await gsFetch(env, a, 'GET', '/shipments/search?code=' + encodeURIComponent(s.gcode));
  const x = (d.data || []).find((r) => r.id === s.gcode) || (d.data || [])[0];
  if (!x) throw new HttpError(404, 'Goship không tìm thấy vận đơn ' + s.gcode);
  await applyRemote(env, a, x);
  return first(env, 'SELECT * FROM goship_shipments WHERE gcode=?', s.gcode);
}
async function applyRemote(env, a, x) {
  const to = x.address_to || {};
  const r = await run(env, `UPDATE goship_shipments SET carrier_code=COALESCE(?,carrier_code), carrier=COALESCE(?,carrier), service=COALESCE(?,service),
      fee=COALESCE(?,fee), amount_return_shop=COALESCE(?,amount_return_shop), status=?, status_text=?, status_desc=?, tracking_url=COALESCE(?,tracking_url),
      updated_at=datetime('now') WHERE gcode=?`,
    x.carrier_code || null, x.carrier_name || null, x.service_name || null, num(x.total_fee), num(x.amount_return_shop),
    num(x.status_code), x.status_text || GS_STATUS[x.status_code] || null, x.status_desc || null, x.tracking_url || null, x.id);
  if (!r.meta?.changes) {
    await run(env, `INSERT OR IGNORE INTO goship_shipments (account_id, gcode, order_id, carrier_code, carrier, service, payer, fee, amount_return_shop, weight,
        status, status_text, status_desc, tracking_url, to_name, to_phone, to_address, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'goship')`,
      a.id, x.id, x.order_id || null, x.carrier_code || null, x.carrier_name || null, x.service_name || null, num(x.payer), num(x.total_fee),
      num(x.amount_return_shop), num(x.parcel?.weight), num(x.status_code), x.status_text || null, x.status_desc || null, x.tracking_url || null,
      to.name || null, to.phone || null, [to.street, to.district, to.city].filter(Boolean).join(', '));
  }
}

// Kéo các vận đơn gần nhất từ Goship về (bổ sung nếu sót webhook)
export async function gsSyncAccount(env, id, pages = 2) {
  const a = await getGsAccount(env, id);
  if (!a) throw new HttpError(404, 'Không có tài khoản Goship');
  let n = 0;
  for (let pg = 1; pg <= pages; pg++) {
    const d = await gsFetch(env, a, 'GET', `/shipments?size=50&page=${pg}`);
    for (const x of d.data || []) { await applyRemote(env, a, x); n++; }
    if (!d.meta?.pagination || pg >= d.meta.pagination.total_pages) break;
  }
  return { ok: true, message: `Đã cập nhật ${n} vận đơn từ Goship` };
}

export async function gsCancel(env, s) {
  const a = await getGsAccount(env, s.account_id);
  if (!a) throw new HttpError(404, 'Tài khoản Goship của vận đơn không còn');
  await gsFetch(env, a, 'DELETE', '/shipments/' + encodeURIComponent(s.gcode));
  await run(env, "UPDATE goship_shipments SET status=914, status_text='Đơn hủy', updated_at=datetime('now') WHERE gcode=?", s.gcode);
  return first(env, 'SELECT * FROM goship_shipments WHERE gcode=?', s.gcode);
}

// Danh sách vận đơn đã lưu. f: {accounts(ids|null), apiKeyId, account, status, q, order_id, from, to, updated_since, page, per_page}
export async function listShipments(env, f) {
  const w = [], args = [];
  if (f.accounts) { w.push(`s.account_id IN (${f.accounts.map(() => '?').join(',')})`); args.push(...f.accounts.map(Number)); }
  if (f.apiKeyId) { w.push('s.api_key_id=?'); args.push(f.apiKeyId); }
  if (f.account) { w.push('s.account_id=?'); args.push(Number(f.account)); }
  if (f.status) { w.push('s.status=?'); args.push(Number(f.status)); }
  if (f.order_id) { w.push('s.order_id=?'); args.push(String(f.order_id)); }
  if (f.q) { w.push('(s.gcode LIKE ? OR s.order_id LIKE ? OR s.carrier_code LIKE ? OR s.to_phone LIKE ? OR s.to_name LIKE ?)'); const q = `%${f.q}%`; args.push(q, q, q, q, q); }
  if (f.from) { w.push('date(s.created_at) >= ?'); args.push(f.from); }
  if (f.to) { w.push('date(s.created_at) <= ?'); args.push(f.to); }
  if (f.updated_since) { w.push('s.updated_at > ?'); args.push(String(f.updated_since).replace('T', ' ').replace('Z', '').slice(0, 19)); }
  const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
  const page = Math.max(1, Number(f.page || 1)), per = Math.min(100, Math.max(1, Number(f.per_page || 50)));
  const total = (await first(env, `SELECT COUNT(*) n FROM goship_shipments s ${where}`, ...args)).n;
  const order = f.updated_since ? 's.updated_at ASC, s.id ASC' : 's.id DESC';
  const rows = await all(env, `SELECT s.*, a.name account_name FROM goship_shipments s LEFT JOIN goship_accounts a ON a.id=s.account_id ${where} ORDER BY ${order} LIMIT ? OFFSET ?`, ...args, per, (page - 1) * per);
  return { rows, total, page, per };
}

// ---------------------------------------------------------------- webhook Goship
export async function handleGsWebhook(request, env, id, token) {
  const raw = await request.text();
  const ip = request.headers.get('cf-connecting-ip') || '';
  const log = async (status, message, gcode = null, st = null) => {
    await run(env, 'INSERT INTO goship_webhook_log (account_id, status, message, gcode, shipment_status, ip) VALUES (?,?,?,?,?,?)', id, status, message, gcode, st, ip).catch(() => {});
    await run(env, 'DELETE FROM goship_webhook_log WHERE id <= (SELECT MAX(id) - 500 FROM goship_webhook_log)').catch(() => {});
  };
  const a = await getGsAccount(env, id);
  if (!a || !timingSafeEqual(token, a.webhook_token)) {
    await log(401, 'Sai URL webhook (mã bí mật trong URL không khớp)');
    return json({ success: false, message: 'unauthorized' }, 401);
  }
  let d;
  try { d = JSON.parse(raw); } catch { await log(400, 'Body không phải JSON'); return json({ success: false, message: 'invalid json' }, 400); }
  let note = '';
  const sig = request.headers.get('x-goship-hmac-sha256');
  if (a.client_secret && sig) note = (await verifyGsHmac(a.client_secret, raw, d, sig)) ? ' · chữ ký HMAC khớp' : ' · chữ ký HMAC không khớp (vẫn nhận vì URL đúng)';
  const gcode = str(d.gcode);
  if (!gcode) { await log(200, 'Không có gcode, bỏ qua (có thể là gói thử)' + note); return json({ success: true }); }
  const st = num(d.status);
  const r = await run(env, `UPDATE goship_shipments SET status=?, status_text=?, status_desc=?, carrier_code=COALESCE(?,carrier_code), tracking_url=COALESCE(?,tracking_url),
      fee=COALESCE(?,fee), cod=COALESCE(?,cod), amount_return_shop=COALESCE(?,amount_return_shop), weight=COALESCE(?,weight), sorting_code=COALESCE(?,sorting_code),
      carrier_short_name=COALESCE(?,carrier_short_name), is_return=?, is_lost=?, updated_at=datetime('now') WHERE gcode=?`,
    st, d.status_text || GS_STATUS[st] || null, d.description || d.message || null, d.code || null, d.tracking_url || null, num(d.fee), num(d.cod),
    num(d.amount_return_shop), num(d.weight), d.sorting_code || null, d.carrier_short_name || null, Number(d.is_return) ? 1 : 0, Number(d.is_lost) ? 1 : 0, gcode);
  if (!r.meta?.changes) {
    await run(env, `INSERT OR IGNORE INTO goship_shipments (account_id, gcode, order_id, carrier_code, carrier_short_name, payer, cod, fee, amount_return_shop, weight,
        status, status_text, status_desc, tracking_url, sorting_code, is_return, is_lost, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'goship')`,
      a.id, gcode, d.order_id || null, d.code || null, d.carrier_short_name || null, num(d.payer), num(d.cod), num(d.fee), num(d.amount_return_shop), num(d.weight),
      st, d.status_text || GS_STATUS[st] || null, d.description || d.message || null, d.tracking_url || null, d.sorting_code || null,
      Number(d.is_return) ? 1 : 0, Number(d.is_lost) ? 1 : 0);
  }
  await log(200, `${gcode}: ${d.status_text || GS_STATUS[st] || st}${r.meta?.changes ? '' : ' (vận đơn mới từ Goship)'}${note}`, gcode, st);
  return json({ success: true });
}

// Goship ký base64(HMAC-SHA256(client_secret, body)); tài liệu có ví dụ khác nhau nên thử vài biến thể
export async function verifyGsHmac(secret, raw, data, sig) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const bodies = [raw, JSON.stringify(data), JSON.stringify(data).replace(/\//g, '\\/')];
  for (const b of bodies) {
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(b)));
    const hex = toHex(mac);
    const b64 = btoa(String.fromCharCode(...mac));
    for (const c of [b64, hex, btoa(hex)]) if (timingSafeEqual(c, sig.trim())) return true;
  }
  return false;
}

// ---------------------------------------------------------------- định dạng trả ra cho API v1
export function v1Shipment(s) {
  return {
    gcode: s.gcode, account_id: s.account_id, order_id: s.order_id, carrier: s.carrier, carrier_short_name: s.carrier_short_name,
    carrier_code: s.carrier_code, service: s.service, payer: s.payer, cod: s.cod, fee: s.fee, amount_return_shop: s.amount_return_shop,
    weight: s.weight, status: s.status, status_text: s.status_text, status_desc: s.status_desc, tracking_url: s.tracking_url,
    sorting_code: s.sorting_code, is_return: s.is_return, is_lost: s.is_lost, receiver: { name: s.to_name, phone: s.to_phone, address: s.to_address },
    carrier_error: s.carrier_error ? safeParse(s.carrier_error) : null, created_at: s.created_at, updated_at: s.updated_at,
    ...(s.duplicate ? { duplicate: true } : {}),
  };
}
const safeParse = (t) => { try { return JSON.parse(t); } catch { return t; } };
