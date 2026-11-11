-- Tích hợp Goship: nhiều tài khoản Goship, vận đơn, nhật ký webhook, quyền Goship cho API key

CREATE TABLE IF NOT EXISTS goship_accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  env TEXT NOT NULL DEFAULT 'production' CHECK (env IN ('sandbox','production')),
  access_token TEXT,
  client_secret TEXT,                 -- tuỳ chọn, dùng kiểm tra chữ ký x-goship-hmac-sha256
  webhook_token TEXT NOT NULL,        -- chuỗi bí mật nằm trong URL webhook
  sender TEXT,                        -- JSON địa chỉ gửi mặc định {name, phone, street, city, district, ward}
  active INTEGER NOT NULL DEFAULT 1,
  last_check_at TEXT,
  last_error TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS goship_shipments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL,
  gcode TEXT NOT NULL UNIQUE,         -- mã vận đơn Goship
  order_id TEXT,                      -- mã đơn của bên tạo
  carrier_code TEXT,                  -- mã vận đơn của hãng
  carrier TEXT,
  carrier_short_name TEXT,
  service TEXT,
  payer INTEGER,
  cod INTEGER DEFAULT 0,
  fee INTEGER DEFAULT 0,
  amount_return_shop INTEGER,
  weight REAL,
  status INTEGER,
  status_text TEXT,
  status_desc TEXT,
  tracking_url TEXT,
  sorting_code TEXT,
  is_return INTEGER DEFAULT 0,
  is_lost INTEGER DEFAULT 0,
  to_name TEXT,
  to_phone TEXT,
  to_address TEXT,
  carrier_error TEXT,
  source TEXT,                        -- 'web:<user>', 'api:<tên key>' hoặc 'goship'
  api_key_id INTEGER,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_gs_account ON goship_shipments(account_id, created_at);
CREATE INDEX IF NOT EXISTS idx_gs_order ON goship_shipments(order_id);
CREATE INDEX IF NOT EXISTS idx_gs_updated ON goship_shipments(updated_at);

CREATE TABLE IF NOT EXISTS goship_webhook_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER,
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  status INTEGER,
  message TEXT,
  gcode TEXT,
  shipment_status INTEGER,
  ip TEXT
);

-- API key: danh sách id tài khoản Goship được dùng (NULL = tất cả). Quyền Goship nằm trong scopes ('goship')
ALTER TABLE api_keys ADD COLUMN goship_accounts TEXT;
