// Tích hợp eSMS (https://developers.esms.vn): nhiều tài khoản, gửi mã OTP xác minh số điện thoại qua SMS, Zalo ZNS hoặc Zalo rồi SMS
import { HttpError, json, all, first, run, enc, toHex, mask, timingSafeEqual } from './lib.js';

const ESMS_BASE = 'https://rest.esms.vn/MainService.svc/json';
const base = (env) => env.ESMS_API_BASE || ESMS_BASE;
export const CHANNELS = { sms: 'SMS', zalo: 'Zalo ZNS', zalo_sms: 'Zalo, lỗi thì SMS' };
export const LIMITS = { resendSeconds: 60, perPhoneHour: 5, maxAttempts: 5 };
const ESMS_ERR = {
  99: 'Số điện thoại bị chặn trên eSMS', 101: 'Sai ApiKey hoặc SecretKey', 102: 'Tài khoản eSMS chưa có bảng giá', 103: 'Tài khoản eSMS không đủ số dư',
  104: 'Brandname chưa đăng ký hoặc chưa kích hoạt', 108: 'Số điện thoại không đúng định dạng', 118: 'Loại tin nhắn không hỗ trợ', 124: 'Trùng RequestId',
  140: 'IP chưa được eSMS whitelist', 143: 'Tài khoản eSMS chưa kích hoạt hoặc bị khoá', 146: 'Nội dung SMS không khớp template CSKH đã đăng ký',
  177: 'Nhà mạng chưa được đăng ký cho brandname', 201: 'Nội dung có từ khoá bị chặn', 204: 'OAID không tồn tại', 789: 'Template ZNS chưa cấu hình cho OA này',
  790: 'Sai template ZNS', 791: 'Thiếu OA ID hoặc Template ID', 799: 'OAID không hoạt động hoặc chưa thêm vào tài khoản eSMS',
};
export const esmsErr = (code, msg) => (ESMS_ERR[code] ? `${ESMS_ERR[code]} (mã ${code})` : `eSMS trả mã ${code}${msg ? ': ' + msg : ''}`);

async function esmsPost(env, path, payload) {
  let r;
  try {
    r = await fetch(base(env) + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  } catch (e) {
    throw new HttpError(502, 'Không gọi được eSMS: ' + (e.message || e));
  }
  const t = await r.text();
  try { return JSON.parse(t); } catch { throw new HttpError(502, `eSMS trả HTTP ${r.status}: ${t.slice(0, 120)}`); }
}

// ---------------------------------------------------------------- số điện thoại
export function normalizePhone(p) {
  let s = String(p || '').replace(/[\s.\-()]/g, '');
  if (s.startsWith('+84')) s = '0' + s.slice(3);
  else if (/^84\d{9}$/.test(s)) s = '0' + s.slice(2);
  if (!/^0\d{9}$/.test(s)) throw new HttpError(422, 'Số điện thoại không hợp lệ (cần 10 số, vd 0901234567)');
  return s;
}
export const maskPhone = (p) => (p ? p.slice(0, 3) + '****' + p.slice(-3) : '');

// ---------------------------------------------------------------- tài khoản
export const getEsmsAccount = (env, id) => first(env, 'SELECT * FROM esms_accounts WHERE id=?', Number(id));
export async function pickEsms(env, id, allowed = null) {
  if (id !== undefined && id !== null && id !== '') {
    if (allowed && !allowed.includes(String(id))) throw new HttpError(403, 'Không được dùng tài khoản eSMS này');
    const a = await getEsmsAccount(env, id);
    if (!a || !a.active) throw new HttpError(404, 'Không có tài khoản eSMS đang hoạt động với id ' + id);
    return a;
  }
  const list = await all(env, 'SELECT * FROM esms_accounts WHERE active=1 ORDER BY id');
  const a = list.find((x) => !allowed || allowed.includes(String(x.id)));
  if (!a) throw new HttpError(400, 'Chưa có tài khoản eSMS nào hoạt động');
  return a;
}
export const channelsOf = (a) => [
  ...(a.brandname && a.sms_template ? ['sms'] : []),
  ...(a.zalo_oaid && a.zalo_temp_id ? ['zalo'] : []),
  ...(a.brandname && a.sms_template && a.zalo_oaid && a.zalo_temp_id ? ['zalo_sms'] : []),
];

export async function esmsAccountsView(env, url) {
  const rows = await all(env, `SELECT a.*, (SELECT COUNT(*) FROM otp_requests o WHERE o.account_id=a.id AND o.created_at >= datetime('now','-1 day')) otp_24h FROM esms_accounts a ORDER BY a.id`);
  return rows.map((a) => ({
    id: a.id, name: a.name, active: a.active, sandbox: a.sandbox, default_channel: a.default_channel, channels: channelsOf(a),
    api_key_set: !!a.api_key, api_key_hint: mask(a.api_key), secret_key_set: !!a.secret_key, secret_key_hint: mask(a.secret_key),
    brandname: a.brandname, sms_template: a.sms_template, zalo_oaid: a.zalo_oaid, zalo_temp_id: a.zalo_temp_id, zalo_param: a.zalo_param,
    otp_length: a.otp_length, otp_ttl: a.otp_ttl, otp_24h: a.otp_24h, last_balance: a.last_balance, last_check_at: a.last_check_at, last_error: a.last_error,
    callback_url: `${url.origin}/api/esms/callback/${a.id}/${a.callback_token}`,
  }));
}

export async function saveEsmsAccount(env, b, url) {
  const fields = [], args = [];
  const set = (f, v) => { fields.push(f + '=?'); args.push(v); };
  const txt = (v, max = 200) => { const s = String(v ?? '').trim(); return s ? s.slice(0, max) : null; };
  if (b.name !== undefined) { if (!txt(b.name)) throw new HttpError(400, 'Cần đặt tên tài khoản eSMS'); set('name', txt(b.name)); }
  if (b.api_key) set('api_key', txt(b.api_key));
  if (b.secret_key) set('secret_key', txt(b.secret_key));
  if (b.brandname !== undefined) set('brandname', txt(b.brandname, 50));
  if (b.sms_template !== undefined) {
    const t = txt(b.sms_template, 500);
    if (t && !t.includes('{code}')) throw new HttpError(400, 'Nội dung SMS phải có {code} ở chỗ điền mã OTP');
    set('sms_template', t);
  }
  if (b.zalo_oaid !== undefined) set('zalo_oaid', txt(b.zalo_oaid, 50));
  if (b.zalo_temp_id !== undefined) set('zalo_temp_id', txt(b.zalo_temp_id, 50));
  if (b.zalo_param !== undefined) set('zalo_param', txt(b.zalo_param, 50) || 'otp');
  if (b.default_channel !== undefined) { if (!CHANNELS[b.default_channel]) throw new HttpError(400, 'Kênh mặc định không hợp lệ'); set('default_channel', b.default_channel); }
  if (b.sandbox !== undefined) set('sandbox', b.sandbox ? 1 : 0);
  if (b.otp_length !== undefined) { const n = Number(b.otp_length); if (!(n >= 4 && n <= 8)) throw new HttpError(400, 'Độ dài mã từ 4 đến 8 số'); set('otp_length', n); }
  if (b.otp_ttl !== undefined) { const n = Number(b.otp_ttl); if (!(n >= 60 && n <= 1800)) throw new HttpError(400, 'Thời hạn mã từ 60 đến 1800 giây'); set('otp_ttl', n); }
  if (b.active !== undefined) set('active', b.active ? 1 : 0);
  if (b.id) {
    if (!(await getEsmsAccount(env, b.id))) throw new HttpError(404, 'Không có tài khoản eSMS');
    if (fields.length) await run(env, `UPDATE esms_accounts SET ${fields.join(', ')} WHERE id=?`, ...args, b.id);
  } else {
    if (!b.name) throw new HttpError(400, 'Cần đặt tên tài khoản eSMS');
    set('callback_token', toHex(crypto.getRandomValues(new Uint8Array(16))));
    const cols = fields.map((f) => f.split('=')[0]);
    await run(env, `INSERT INTO esms_accounts (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`, ...args);
  }
  return json(await esmsAccountsView(env, url));
}

export async function testEsmsAccount(env, id) {
  const a = await getEsmsAccount(env, id);
  if (!a) return { ok: false, message: 'Không có tài khoản eSMS' };
  if (!a.api_key || !a.secret_key) return { ok: false, message: 'Chưa nhập ApiKey và SecretKey' };
  try {
    const d = await esmsPost(env, '/GetBalance_json', { ApiKey: a.api_key, SecretKey: a.secret_key });
    const code = String(d.CodeResponse ?? d.CodeResult ?? '');
    if (code !== '100') throw new HttpError(502, esmsErr(code, d.ErrorMessage));
    await run(env, "UPDATE esms_accounts SET last_balance=?, last_check_at=datetime('now'), last_error=NULL WHERE id=?", Number(d.Balance) || 0, a.id);
    return { ok: true, balance: Number(d.Balance) || 0, message: `Kết nối thành công, số dư ${Number(d.Balance || 0).toLocaleString('vi-VN')}đ` };
  } catch (e) {
    await run(env, "UPDATE esms_accounts SET last_check_at=datetime('now'), last_error=? WHERE id=?", e.message, a.id);
    return { ok: false, message: e.message };
  }
}

// ---------------------------------------------------------------- OTP
const genCode = (len) => { const b = crypto.getRandomValues(new Uint32Array(len)); return [...b].map((x) => x % 10).join(''); };
const hashCode = async (pepper, rid, code) => {
  const key = await crypto.subtle.importKey('raw', enc.encode(pepper), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', key, enc.encode(rid + ':' + code)));
};

// b: {phone, channel?, purpose?}; ctx: {pepper, origin, source, apiKeyId, ip}
export async function sendOtp(env, a, b, ctx) {
  const phone = normalizePhone(b.phone);
  const channel = b.channel || a.default_channel;
  if (!CHANNELS[channel]) throw new HttpError(422, 'channel chỉ nhận sms, zalo hoặc zalo_sms');
  if (!channelsOf(a).includes(channel)) throw new HttpError(422, `Tài khoản eSMS "${a.name}" chưa cấu hình kênh ${CHANNELS[channel]}`);
  if (!a.api_key || !a.secret_key) throw new HttpError(400, `Tài khoản eSMS "${a.name}" chưa có ApiKey/SecretKey`);
  const last = await first(env, `SELECT created_at FROM otp_requests WHERE phone=? AND account_id=? AND send_code='100' AND created_at > datetime('now', ?) ORDER BY id DESC LIMIT 1`, phone, a.id, `-${LIMITS.resendSeconds} seconds`);
  if (last) throw new HttpError(429, `Vừa gửi mã cho số này, chờ ${LIMITS.resendSeconds} giây rồi thử lại`);
  const hour = await first(env, `SELECT COUNT(*) n FROM otp_requests WHERE phone=? AND send_code='100' AND created_at > datetime('now','-1 hour')`, phone);
  if (hour.n >= LIMITS.perPhoneHour) throw new HttpError(429, `Số này đã nhận ${LIMITS.perPhoneHour} mã trong 1 giờ, thử lại sau`);

  const rid = 'otp' + toHex(crypto.getRandomValues(new Uint8Array(16)));
  const code = genCode(a.otp_length || 6);
  const cb = `${ctx.origin}/api/esms/callback/${a.id}/${a.callback_token}`;
  const sandbox = a.sandbox ? '1' : '0';
  const sms = { Content: a.sms_template?.replaceAll('{code}', code), IsUnicode: '0', SmsType: '2', Brandname: a.brandname, CallbackUrl: cb, Sandbox: sandbox };
  let path, payload;
  if (channel === 'sms') {
    path = '/SendMultipleMessage_V4_post_json/';
    payload = { ApiKey: a.api_key, SecretKey: a.secret_key, Phone: phone, ...sms, RequestId: rid };
  } else if (channel === 'zalo') {
    path = '/SendZaloMessage_V6/';
    payload = { ApiKey: a.api_key, SecretKey: a.secret_key, Phone: phone, OAID: a.zalo_oaid, TempID: a.zalo_temp_id, TempData: { [a.zalo_param || 'otp']: code }, CallbackUrl: cb, RequestId: rid, Sandbox: sandbox };
  } else {
    path = '/MultiChannelMessage/';
    payload = { ApiKey: a.api_key, SecretKey: a.secret_key, Phone: phone, Channels: ['zalo', 'sms'],
      Data: [{ TempID: a.zalo_temp_id, Params: [code], OAID: a.zalo_oaid, CallbackUrl: cb, RequestId: rid + 'z', Sandbox: sandbox }, { ...sms, RequestId: rid + 's' }] };
  }
  const d = await esmsPost(env, path, payload);
  const sc = String(d.CodeResult ?? d.CodeResponse ?? '');
  const ok = sc === '100';
  const ttl = a.otp_ttl || 300;
  await run(env, `INSERT INTO otp_requests (request_id, account_id, phone, channel, purpose, code_hash, status, sms_id, send_code, send_error, api_key_id, source, ip, expires_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?, datetime('now', ?))`,
    rid, a.id, phone, channel, b.purpose ? String(b.purpose).slice(0, 100) : null, await hashCode(ctx.pepper, rid, code), ok ? 'sent' : 'failed',
    d.SMSID || null, sc || null, ok ? null : esmsErr(sc, d.ErrorMessage || d.error), ctx.apiKeyId || null, ctx.source, ctx.ip || null, `+${ttl} seconds`);
  if (!ok) throw new HttpError(502, 'Gửi mã thất bại: ' + esmsErr(sc, d.ErrorMessage || d.error));
  return otpView(await first(env, 'SELECT * FROM otp_requests WHERE request_id=?', rid));
}

// Kiểm tra mã. Trả {verified, status, attempts_left, message}
export async function verifyOtp(env, rid, code, pepper, apiKeyId = null) {
  const o = await first(env, `SELECT *, expires_at < datetime('now') expired FROM otp_requests WHERE request_id=? ${apiKeyId ? 'AND api_key_id=?' : ''}`, ...[String(rid || ''), ...(apiKeyId ? [apiKeyId] : [])]);
  if (!o) throw new HttpError(404, 'Không tìm thấy request_id');
  const left = () => Math.max(0, LIMITS.maxAttempts - o.attempts);
  if (o.status === 'verified') return { verified: true, status: 'verified', phone: o.phone, attempts_left: left(), message: 'Mã đã được xác minh trước đó' };
  if (o.status === 'failed') return { verified: false, status: 'failed', attempts_left: 0, message: 'Mã này gửi không thành công, hãy gửi mã mới' };
  if (o.status === 'locked' || o.attempts >= LIMITS.maxAttempts) return { verified: false, status: 'locked', attempts_left: 0, message: 'Nhập sai quá số lần cho phép, hãy gửi mã mới' };
  if (o.expired || o.status === 'expired') { await run(env, "UPDATE otp_requests SET status='expired' WHERE id=?", o.id); return { verified: false, status: 'expired', attempts_left: 0, message: 'Mã đã hết hạn, hãy gửi mã mới' }; }
  const c = String(code ?? '').trim();
  const good = /^\d{4,8}$/.test(c) && timingSafeEqual(await hashCode(pepper, o.request_id, c), o.code_hash);
  if (good) {
    await run(env, "UPDATE otp_requests SET status='verified', verified_at=datetime('now'), attempts=attempts+1 WHERE id=? AND status='sent'", o.id);
    return { verified: true, status: 'verified', phone: o.phone, attempts_left: Math.max(0, LIMITS.maxAttempts - o.attempts - 1), message: 'Xác minh thành công' };
  }
  o.attempts += 1;
  await run(env, `UPDATE otp_requests SET attempts=attempts+1, status=CASE WHEN attempts+1 >= ? THEN 'locked' ELSE status END WHERE id=?`, LIMITS.maxAttempts, o.id);
  return { verified: false, status: left() ? 'sent' : 'locked', attempts_left: left(), message: left() ? `Mã không đúng, còn ${left()} lần thử` : 'Nhập sai quá số lần cho phép, hãy gửi mã mới' };
}

export function otpView(o) {
  if (!o) return null;
  return { request_id: o.request_id, account_id: o.account_id, phone: o.phone, phone_masked: maskPhone(o.phone), channel: o.channel, purpose: o.purpose,
    status: o.status, attempts: o.attempts, delivery: o.delivery, send_error: o.send_error, created_at: o.created_at, expires_at: o.expires_at, verified_at: o.verified_at };
}

export async function listOtp(env, f) {
  const w = [], args = [];
  if (f.account) { w.push('o.account_id=?'); args.push(Number(f.account)); }
  if (f.apiKeyId) { w.push('o.api_key_id=?'); args.push(f.apiKeyId); }
  if (f.phone) { w.push('o.phone LIKE ?'); args.push('%' + String(f.phone).replace(/\D/g, '') + '%'); }
  if (f.status) { w.push('o.status=?'); args.push(String(f.status)); }
  const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
  const per = Math.min(100, Math.max(1, Number(f.per_page || 50))), page = Math.max(1, Number(f.page || 1));
  await run(env, "UPDATE otp_requests SET status='expired' WHERE status='sent' AND expires_at < datetime('now')");
  const total = (await first(env, `SELECT COUNT(*) n FROM otp_requests o ${where}`, ...args)).n;
  const rows = await all(env, `SELECT o.*, a.name account_name FROM otp_requests o LEFT JOIN esms_accounts a ON a.id=o.account_id ${where} ORDER BY o.id DESC LIMIT ? OFFSET ?`, ...args, per, (page - 1) * per);
  return { rows: rows.map((o) => ({ ...otpView(o), account_name: o.account_name, source: o.source, send_code: o.send_code, delivery_info: o.delivery_info })), total, page, per };
}

// eSMS gọi GET về khi có trạng thái cuối của tin
export async function handleEsmsCallback(request, env, url, id, token) {
  const a = await getEsmsAccount(env, id);
  if (!a || !timingSafeEqual(token, a.callback_token)) return json({ success: false }, 401);
  const q = url.searchParams;
  const smsId = q.get('SMSID') || q.get('smsid') || '';
  const reqId = (q.get('RequestId') || '').replace(/[zs]$/, '');
  const st = Number(q.get('SendStatus')), okN = Number(q.get('SendSuccess') || 0), failN = Number(q.get('SendFailed') || 0);
  const delivery = st === 4 || (st === 5 && failN > 0 && okN === 0) ? 'failed' : st === 5 && okN > 0 ? 'delivered' : null;
  const info = [q.get('TypeId') ? 'TypeId ' + q.get('TypeId') : '', q.get('error_info') || ''].filter(Boolean).join(' · ').slice(0, 500);
  if (delivery) {
    await run(env, `UPDATE otp_requests SET delivery=CASE WHEN delivery='delivered' THEN delivery ELSE ? END, delivery_info=? WHERE account_id=? AND (sms_id=? OR request_id=?)`,
      delivery, info || null, a.id, smsId, reqId || '-');
  }
  return json({ success: true });
}
