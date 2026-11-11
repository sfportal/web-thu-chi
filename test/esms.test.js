import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizePhone, maskPhone, esmsErr } from '../src/esms.js';

test('normalizePhone chuẩn hoá +84, 84 và khoảng trắng', () => {
  assert.equal(normalizePhone('+84 901 888 484'), '0901888484');
  assert.equal(normalizePhone('84901888484'), '0901888484');
  assert.equal(normalizePhone('0901.888.484'), '0901888484');
  assert.throws(() => normalizePhone('12345'), /không hợp lệ/);
});

test('maskPhone và thông báo lỗi eSMS', () => {
  assert.equal(maskPhone('0901888484'), '090****484');
  assert.match(esmsErr('103'), /không đủ số dư/);
  assert.match(esmsErr('555', 'abc'), /555: abc/);
});
