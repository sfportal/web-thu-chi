-- Nhiều kết nối SePay, API key cho bên thứ 3, giới hạn tài khoản ngân hàng theo người dùng

CREATE TABLE IF NOT EXISTS sepay_connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  sepay_env TEXT NOT NULL DEFAULT 'production' CHECK (sepay_env IN ('sandbox','production')),
  webhook_auth TEXT NOT NULL DEFAULT 'hmac' CHECK (webhook_auth IN ('hmac','apikey','none')),
  api_token TEXT,
  webhook_secret TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  last_sync_at TEXT,
  last_sync_error TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Chuyển thiết lập SePay đơn lẻ trước đây thành kết nối số 1 (giữ nguyên URL webhook cũ)
INSERT INTO sepay_connections (id, name, sepay_env, webhook_auth, api_token, webhook_secret)
SELECT 1, 'SePay chính',
  COALESCE((SELECT value FROM settings WHERE key='sepay_env'), 'production'),
  COALESCE((SELECT value FROM settings WHERE key='webhook_auth'), 'hmac'),
  (SELECT value FROM settings WHERE key='sepay_api_token'),
  (SELECT value FROM settings WHERE key='sepay_webhook_secret')
WHERE EXISTS (SELECT 1 FROM settings WHERE key IN ('sepay_api_token','sepay_webhook_secret'))
  AND NOT EXISTS (SELECT 1 FROM sepay_connections);

ALTER TABLE transactions ADD COLUMN connection_id INTEGER;
ALTER TABLE bank_accounts ADD COLUMN connection_id INTEGER;
ALTER TABLE webhook_log ADD COLUMN connection_id INTEGER;
ALTER TABLE sync_log ADD COLUMN connection_id INTEGER;

UPDATE transactions SET connection_id = 1 WHERE source != 'manual' AND EXISTS (SELECT 1 FROM sepay_connections WHERE id = 1);
UPDATE bank_accounts SET connection_id = 1 WHERE EXISTS (SELECT 1 FROM sepay_connections WHERE id = 1);
UPDATE webhook_log SET connection_id = 1 WHERE EXISTS (SELECT 1 FROM sepay_connections WHERE id = 1);
UPDATE sync_log SET connection_id = 1 WHERE EXISTS (SELECT 1 FROM sepay_connections WHERE id = 1);

DELETE FROM settings WHERE key IN ('sepay_api_token','sepay_webhook_secret','sepay_env','webhook_auth');

-- API key cho bên thứ 3 (chỉ lưu SHA-256 của key)
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL DEFAULT 'read',          -- 'read' hoặc 'read,write'
  accounts TEXT,                                -- danh sách số tài khoản được xem, NULL = tất cả
  active INTEGER NOT NULL DEFAULT 1,
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT
);

-- Tài khoản ngân hàng được phép xem của từng người dùng (trống = tất cả)
CREATE TABLE IF NOT EXISTS user_accounts (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  account_number TEXT NOT NULL,
  PRIMARY KEY (user_id, account_number)
);

CREATE INDEX IF NOT EXISTS idx_txn_account ON transactions(account_number, txn_date);
