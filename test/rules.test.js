import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalize, matchRule, hmacHex } from '../src/index.js';

test('normalize bỏ dấu tiếng Việt', () => {
  assert.equal(normalize('Thanh toán PHÍ Mã Vùng Đắk Lắk'), 'thanh toan phi ma vung dak lak');
});

test('matchRule theo từ khoá, chiều và ưu tiên', () => {
  const rules = [
    { id: 1, pattern: 'luong', match_type: 'contains', transfer_type: 'out', category_id: 6, priority: 10 },
    { id: 2, pattern: 'msvt|ma vung', match_type: 'contains', transfer_type: 'in', category_id: 1, priority: 20 },
    { id: 3, pattern: '^ck\\s+\\d+', match_type: 'regex', transfer_type: 'any', category_id: 9, priority: 30 },
  ];
  assert.equal(matchRule(rules, { type: 'out', content: 'Chuyen LƯƠNG thang 10' }).id, 1);
  assert.equal(matchRule(rules, { type: 'in', content: 'HTX Ea Kiet phi Mã vùng dot 1' }).id, 2);
  assert.equal(matchRule(rules, { type: 'out', content: 'phi MSVT' }), null);
  assert.equal(matchRule(rules, { type: 'in', content: 'CK 12345 abc' }).id, 3);
});

test('HMAC đúng chuẩn SePay', async () => {
  const sig = await hmacHex('secret', '1700000000.{"a":1}');
  assert.match(sig, /^[0-9a-f]{64}$/);
});
