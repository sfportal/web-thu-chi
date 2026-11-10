-- Nhật ký mọi lần SePay gọi webhook (kể cả lỗi xác thực) để chẩn đoán
CREATE TABLE IF NOT EXISTS webhook_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at TEXT NOT NULL DEFAULT (datetime('now')),
  status INTEGER NOT NULL,
  message TEXT,
  sepay_id TEXT,
  amount INTEGER,
  transfer_type TEXT,
  ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_webhook_log_time ON webhook_log(received_at);
