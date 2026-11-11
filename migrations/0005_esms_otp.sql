-- Tích hợp eSMS: nhiều tài khoản eSMS, mã OTP xác minh số điện thoại qua SMS / Zalo ZNS, quyền OTP cho API key

CREATE TABLE IF NOT EXISTS esms_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  api_key TEXT,
  secret_key TEXT,
  brandname TEXT,                                   -- Brandname SMS đã đăng ký
  sms_template TEXT,                                -- nội dung SMS đã đăng ký, {code} là chỗ điền mã
  zalo_oaid TEXT,                                   -- Zalo OA ID
  zalo_temp_id TEXT,                                -- Template ZNS OTP
  zalo_param TEXT NOT NULL DEFAULT 'otp',           -- tên tham số mã trong template ZNS
  default_channel TEXT NOT NULL DEFAULT 'sms' CHECK (default_channel IN ('sms','zalo','zalo_sms')),
  sandbox INTEGER NOT NULL DEFAULT 0,
  otp_length INTEGER NOT NULL DEFAULT 6,
  otp_ttl INTEGER NOT NULL DEFAULT 300,             -- giây
  callback_token TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  last_balance REAL,
  last_check_at TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS otp_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL UNIQUE,
  account_id INTEGER NOT NULL,
  phone TEXT NOT NULL,
  channel TEXT NOT NULL,
  purpose TEXT,
  code_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'sent',              -- sent, verified, failed, expired, locked
  attempts INTEGER NOT NULL DEFAULT 0,
  sms_id TEXT,
  send_code TEXT,                                   -- CodeResult eSMS trả về
  send_error TEXT,
  delivery TEXT,                                    -- delivered, failed (theo callback eSMS)
  delivery_info TEXT,
  api_key_id INTEGER,
  source TEXT,
  ip TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  verified_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_requests(phone, created_at);
CREATE INDEX IF NOT EXISTS idx_otp_sms ON otp_requests(sms_id);

ALTER TABLE api_keys ADD COLUMN otp_accounts TEXT;
