# Web thu chi SePay

Webtool quản lý thu chi tự động: mọi giao dịch ngân hàng liên kết với [SePay](https://developer.sepay.vn/vi) được ghi nhận theo thời gian thực, tự phân loại theo danh mục, đối soát định kỳ, kèm thu tiền bằng QR theo mã đơn. Chạy trên **Cloudflare Workers + D1**.

## Tính năng

- **Nhận webhook SePay** tại `/api/sepay/webhook`, xác thực HMAC-SHA256 (hoặc API Key), chống trùng theo `id` giao dịch, trả `{"success": true}` đúng chuẩn SePay.
- **Đối soát tự động mỗi 30 phút** qua SePay API v2 (`/v2/transactions`, `/v2/bank-accounts`): bổ sung giao dịch webhook bị sót, cập nhật số dư. Chống trùng chéo giữa webhook và API (theo tài khoản + mã tham chiếu + số tiền).
- **Tự phân loại** theo quy tắc từ khoá trong nội dung chuyển khoản (không phân biệt dấu, hỗ trợ regex). Sửa tay được, quy tắc không ghi đè phân loại tay.
- **Nhập tay** giao dịch tiền mặt.
- **Tổng quan**: tổng thu, chi, chênh lệch; biểu đồ theo tháng; thu chi theo danh mục; số dư từng tài khoản.
- **Thu tiền QR**: tạo yêu cầu thu với mã (vd `TT123456`), sinh ảnh VietQR; tiền về khớp mã thì tự chuyển “Đã thu” và gắn danh mục.
- **Xuất CSV** (mở được bằng Excel, có BOM UTF-8).
- **Người dùng & phân quyền**: Quản trị / Biên tập / Chỉ xem.

## Cài đặt và deploy

Yêu cầu: Node.js 18+, tài khoản Cloudflare, tài khoản SePay đã liên kết ngân hàng.

```bash
npm install
npx wrangler login
npx wrangler d1 create sepay-thuchi        # chép database_id in ra vào wrangler.toml
npm run db:migrate                          # tạo bảng trên D1

# Bí mật duy nhất cần đặt: mật khẩu tài khoản "admin" đầu tiên
npx wrangler secret put ADMIN_PASSWORD

npm run deploy
```

Sau khi deploy:

1. Mở `https://<worker>.workers.dev`, đăng nhập `admin` với `ADMIN_PASSWORD`. Đổi mật khẩu, thêm người dùng ở tab **Quản trị**.
2. Vào tab **Thiết lập SePay** và làm theo 4 bước trên màn hình: chọn Test mode hoặc Production, dán API Token, tạo Secret Key rồi khai báo webhook trên my.sepay.vn, bấm **Kiểm tra kết nối API**.
3. Muốn dùng QR thu tiền: khai báo tiền tố mã (mặc định `TT`) ở my.sepay.vn → Cấu hình công ty → Cấu trúc mã thanh toán, và nhập STK nhận tiền ở tab **Quản trị**.

Token và Secret nhập trên giao diện được lưu trong D1, không bao giờ trả về trình duyệt (chỉ hiện 4 ký tự cuối). Nếu muốn, vẫn có thể đặt bằng `wrangler secret put SEPAY_API_TOKEN` / `SEPAY_WEBHOOK_SECRET`; giá trị nhập trên giao diện được ưu tiên.

### Test mode trước, thật sau

Ở tab **Thiết lập SePay**, chọn Test mode để dùng `userapi-sandbox.sepay.vn` và token tạo trong Test mode của my.sepay.vn. Thử với giao dịch mô phỏng xong, chuyển sang Production, dán token thật và tạo webhook Live trỏ về cùng URL.

## Chạy thử trên máy

```bash
cp .dev.vars.example .dev.vars
npm run db:migrate:local
npm run dev            # http://localhost:8787, đăng nhập admin / admin12345
npm test
```

## Cấu hình (`wrangler.toml` → `[vars]`)

| Biến | Ý nghĩa |
|---|---|
| `SEPAY_ENV` | `sandbox` hoặc `production` |
| `WEBHOOK_AUTH` | `hmac` (khuyến nghị), `apikey` hoặc `none` |
| `SYNC_LOOKBACK_HOURS` | số giờ quét lại mỗi lần đối soát (mặc định 48) |

## Lưu ý từ tài liệu SePay

- API Token của SePay có **toàn quyền**, chỉ đặt làm secret trên Worker, không đưa ra trình duyệt.
- API giới hạn **3 request/giây** mỗi IP; code đã giãn cách và tự chờ khi gặp 429.
- Webhook phải trả HTTP 200 + `{"success": true}` trong 30 giây; SePay retry tối đa 7 lần trong ~33 phút, phần còn lại do đối soát định kỳ bù.
- Một số ngân hàng không trả số dư (`accumulated = 0`); khi đó số dư lấy từ API tài khoản.

## Cấu trúc

```
src/index.js              Worker: webhook, API, đối soát (cron), phiên đăng nhập
public/index.html         Giao diện (HTML + JS thuần, không cần build)
migrations/0001_init.sql  Schema D1 + danh mục mặc định
test/                     Kiểm thử quy tắc phân loại, HMAC
```
