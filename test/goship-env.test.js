import { test } from 'node:test';
import assert from 'node:assert/strict';
import { testGsAccount } from '../src/goship.js';

// D1 giả: chỉ đủ cho getGsAccount và các UPDATE
function fakeDb(row) {
  const updates = [];
  return {
    updates,
    prepare: (sql) => ({ bind: (...args) => ({
      first: async () => (sql.startsWith('SELECT') ? row : null),
      run: async () => { updates.push([sql, args]); if (sql.startsWith('UPDATE goship_accounts SET env=?')) row.env = args[0]; return { meta: { changes: 1 } }; },
      all: async () => ({ results: [] }),
    }) }),
  };
}

test('token Production nhưng chọn Sandbox thì tự chuyển sang Production', async () => {
  const row = { id: 1, name: 'dala', env: 'sandbox', access_token: 'eyJprod' };
  const env = { DB: fakeDb(row) };
  globalThis.fetch = async (u) => new Response(JSON.stringify(u.startsWith('https://api.goship.io') ? { code: 200, status: 'success', data: [{ id: '1' }] } : { code: 401, status: 'error' }), { status: u.startsWith('https://api.goship.io') ? 200 : 401 });
  const r = await testGsAccount(env, 1);
  assert.equal(r.ok, true);
  assert.equal(r.switched, 'production');
  assert.equal(row.env, 'production');
});

test('token sai ở cả hai môi trường thì báo lấy lại token', async () => {
  const row = { id: 1, name: 'dala', env: 'sandbox', access_token: 'eyJbad' };
  globalThis.fetch = async () => new Response(JSON.stringify({ code: 401, status: 'error' }), { status: 401 });
  const r = await testGsAccount({ DB: fakeDb(row) }, 1);
  assert.equal(r.ok, false);
  assert.match(r.message, /cả Sandbox và Production/);
});
