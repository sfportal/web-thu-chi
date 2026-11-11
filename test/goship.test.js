import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { verifyGsHmac, parcel, gsErrMsg } from '../src/goship.js';

test('verifyGsHmac nhận chữ ký base64 HMAC-SHA256 của body', async () => {
  const raw = JSON.stringify({ gcode: 'GS1', status: '905' });
  const sig = createHmac('sha256', 'bestshop_secret').update(raw).digest('base64');
  assert.equal(await verifyGsHmac('bestshop_secret', raw, JSON.parse(raw), sig), true);
  assert.equal(await verifyGsHmac('sai_secret', raw, JSON.parse(raw), sig), false);
});

test('parcel kiểm tra cân nặng và điền kích thước mặc định', () => {
  assert.deepEqual(parcel({ weight: '500', cod: '100000' }), { cod: 100000, amount: 0, weight: 500, width: 10, height: 10, length: 10 });
  assert.throws(() => parcel({ cod: 1 }), /weight/);
  assert.throws(() => parcel({ weight: 100, cod: -5 }), /cod/);
});

test('gsErrMsg gộp lỗi validate của Goship', () => {
  const d = { code: 422, status: 'error', data: { errors: { 'shipment.parcel.weight': ['Thiếu thông tin cân nặng'], x: ['Lỗi khác'] } } };
  assert.equal(gsErrMsg(d, 422), 'Thiếu thông tin cân nặng; Lỗi khác');
});
