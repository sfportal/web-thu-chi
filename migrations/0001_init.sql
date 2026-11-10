-- Webtool thu chi SePay: schema D1
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin','editor','viewer')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS bank_accounts (
  account_number TEXT PRIMARY KEY,
  sepay_id TEXT UNIQUE,
  bank TEXT,
  holder TEXT,
  label TEXT,
  balance INTEGER,
  last_transaction TEXT,
  synced_at TEXT
);

CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('in','out')),
  color TEXT DEFAULT '#64748b',
  sort INTEGER DEFAULT 0,
  UNIQUE(name, type)
);

CREATE TABLE IF NOT EXISTS rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT NOT NULL,
  match_type TEXT NOT NULL DEFAULT 'contains' CHECK (match_type IN ('contains','regex')),
  transfer_type TEXT NOT NULL DEFAULT 'any' CHECK (transfer_type IN ('in','out','any')),
  category_id INTEGER REFERENCES categories(id) ON DELETE CASCADE,
  tag TEXT,
  priority INTEGER NOT NULL DEFAULT 100,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL CHECK (source IN ('webhook','api','manual')),
  sepay_webhook_id INTEGER UNIQUE,
  sepay_uuid TEXT UNIQUE,
  reference_code TEXT,
  account_number TEXT,
  bank TEXT,
  txn_date TEXT NOT NULL,            -- 'YYYY-MM-DD HH:mm:ss' giờ Việt Nam
  type TEXT NOT NULL CHECK (type IN ('in','out')),
  amount INTEGER NOT NULL CHECK (amount >= 0),
  content TEXT,
  description TEXT,
  code TEXT,
  sub_account TEXT,
  accumulated INTEGER,
  category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
  tag TEXT,
  note TEXT,
  categorized_by TEXT,               -- 'rule' | 'user' | NULL
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_txn_date ON transactions(txn_date);
CREATE INDEX IF NOT EXISTS idx_txn_ref ON transactions(account_number, reference_code);
CREATE INDEX IF NOT EXISTS idx_txn_cat ON transactions(category_id);
CREATE INDEX IF NOT EXISTS idx_txn_code ON transactions(code);

CREATE TABLE IF NOT EXISTS payment_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  amount INTEGER NOT NULL,
  customer TEXT,
  description TEXT,
  account_number TEXT,
  bank TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','paid','cancelled')),
  paid_amount INTEGER DEFAULT 0,
  paid_txn_id INTEGER REFERENCES transactions(id),
  category_id INTEGER REFERENCES categories(id),
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  paid_at TEXT
);

CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS sync_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL DEFAULT (datetime('now')),
  finished_at TEXT,
  fetched INTEGER DEFAULT 0,
  inserted INTEGER DEFAULT 0,
  error TEXT
);

-- Danh mục mặc định theo hoạt động BVI / FarmBase (sửa được trong giao diện)
INSERT OR IGNORE INTO categories (name, type, color, sort) VALUES
 ('Dịch vụ mã số vùng trồng', 'in', '#16a34a', 1),
 ('Phần mềm FarmBase', 'in', '#0d9488', 2),
 ('Nhập liệu, truy xuất', 'in', '#2563eb', 3),
 ('Đào tạo, tập huấn', 'in', '#7c3aed', 4),
 ('Thu khác', 'in', '#64748b', 9),
 ('Lương, nhân sự', 'out', '#dc2626', 1),
 ('Hạ tầng IT', 'out', '#ea580c', 2),
 ('Xe, xăng, công tác', 'out', '#d97706', 3),
 ('Hiện trường (flycam, in ấn, công văn)', 'out', '#ca8a04', 4),
 ('Hoa hồng CTV, đại lý', 'out', '#db2777', 5),
 ('Marketing, hội thảo', 'out', '#9333ea', 6),
 ('Thuế, phí ngân hàng', 'out', '#475569', 7),
 ('Chi khác', 'out', '#64748b', 9);
