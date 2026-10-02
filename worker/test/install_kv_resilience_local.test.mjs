import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { DatabaseSync } from 'node:sqlite'
import vm from 'node:vm'

// العلّة التي أُبلغ عنها: مكافأة أول تثبيت «لا تعمل» وعدد التثبيتات ثابت.
// السبب أن كتابة KV بلغت حدّها اليومي، و`trackDeviceFarm` كان يكتب في كل
// طلب بلا حماية، فيصعد الفشل إلى 500 ويسقط /v1/install كاملاً — فلا صفّ
// تثبيت ولا مكافأة. هذه الاختبارات تثبّت أن تعذّر KV لا يُسقط أي طلب.
const source = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')
const js = stripTypeScriptTypes(source, { mode: 'transform' })
const schema = readFileSync(new URL('../schema.sql', import.meta.url), 'utf8')

const failingKv = {
  async get() { throw new Error('KV get() limit exceeded') },
  async put() { throw new Error('KV put() limit exceeded for the day.') },
  async delete() { throw new Error('KV delete() limit exceeded') },
}
const workingKv = {
  store: new Map(),
  async get(k, type) {
    const v = this.store.get(k)
    if (v === undefined) return null
    return type === 'json' ? JSON.parse(v) : v
  },
  async put(k, v) { this.store.set(k, v) },
  async delete(k) { this.store.delete(k) },
}

function database() {
  const sql = new DatabaseSync(':memory:')
  const db = {
    sql,
    prepare(text) {
      let args = []
      const run = () => {
        const stmt = sql.prepare(text.replace(/\?(\d+)/g, ':p$1'))
        const bindings = Object.fromEntries(args.map((v, i) => [`p${i + 1}`, v]))
        stmt.setAllowUnknownNamedParameters(true)
        const results = stmt.all(bindings)
        return { results, success: true, meta: { changes: sql.prepare('SELECT changes() n').get().n } }
      }
      return {
        bind(...values) { args = values; return this },
        async first() { return run().results[0] ?? null },
        async all() { return run() },
        async run() { return run() },
      }
    },
    async batch(statements) {
      const out = []
      for (const s of statements) out.push(await s.all())
      return out
    },
  }
  return db
}

function fixture(kv) {
  const XDB = database()
  XDB.sql.exec(schema)
  XDB.sql.exec('CREATE TABLE IF NOT EXISTS x_guest_wallets (device_id TEXT PRIMARY KEY, balance INTEGER, expires_at INTEGER, created_at TEXT, updated_at TEXT)')
  const env = { XDB, QUOTA: kv }
  const context = vm.createContext({ Request, Response, URL, TextEncoder, TextDecoder, crypto, console, atob, btoa })
  vm.runInContext(js.replace('export default', 'const worker ='), context)
  vm.runInContext('logSecurity = async () => {};', context)
  context.env = env
  return { env, context }
}

const installRoute = js.slice(
  js.indexOf("if (path === '/v1/install' && request.method === 'POST')"),
  js.indexOf("if (path === '/v1/install/key' && request.method === 'POST')"))

test('trackDeviceFarm survives a KV write failure without throwing', async () => {
  const f = fixture(failingKv)
  f.context.request = new Request('http://localhost/v1/install', {
    method: 'POST', headers: { 'x-device-id': 'dev-1' },
  })
  await vm.runInContext('trackDeviceFarm(env, request)', f.context)
  assert.ok(true)
})

test('cached() returns the built value even when the KV write fails', async () => {
  const f = fixture(failingKv)
  const value = await vm.runInContext(
    "cached(env, 'catalog:brands', 60, async () => [{ id: 'apple' }])", f.context)
  assert.equal(value.length, 1)
  assert.equal(value[0].id, 'apple')
})

test('grant cap reads survive a KV failure without throwing', async () => {
  const f = fixture(failingKv)
  f.context.request = new Request('http://localhost/v1/install', {
    method: 'POST', headers: { 'x-forwarded-for': '1.2.3.4' },
  })
  const reached = await vm.runInContext(
    "grantCapReached(env, request, 'install')", f.context)
  assert.equal(reached, false)
  await vm.runInContext("grantCapBump(env, request, 'install')", f.context)
  assert.ok(true)
})

test('/v1/install still records the install and grants 50 with KV writes failing', async () => {
  const f = fixture(failingKv)
  f.context.settings = { installBonus: 50, dailyFreeQuota: 5, compatSearchCost: 1 }
  f.context.path = '/v1/install'
  f.context.request = new Request('http://localhost/v1/install', {
    method: 'POST',
    headers: { 'x-device-fp': 'a'.repeat(32), 'x-device-id': 'dev-1' },
    body: JSON.stringify({ installId: 'install-1', appVersion: '22' }),
  })
  vm.runInContext(`
    rateLimit = async () => {};
    walletOf = async () => 'fp:' + 'a'.repeat(32);
    ip = () => '1.2.3.4';
    grantCapReached = async () => false;
    grantCapBump = async () => {};
    verifiedInstallOf = () => 'install-1';
  `, f.context)
  const res = await vm.runInContext(`(async () => { ${installRoute} })()`, f.context)
  assert.equal(res.status, 200)
  const body = await res.json()
  assert.equal(body.bonus, 50)
  assert.equal(f.env.XDB.sql.prepare('SELECT COUNT(*) n FROM x_installs').get().n, 1)
  assert.equal(f.env.XDB.sql.prepare('SELECT balance FROM x_guest_wallets').get().balance, 50)
  assert.equal(f.env.XDB.sql.prepare('SELECT COUNT(*) n FROM x_install_bonus').get().n, 1)
})

test('a healthy KV still grants the bonus exactly once per device', async () => {
  const f = fixture(workingKv)
  f.context.settings = { installBonus: 50, dailyFreeQuota: 5, compatSearchCost: 1 }
  f.context.path = '/v1/install'
  vm.runInContext(`
    rateLimit = async () => {};
    walletOf = async () => 'fp:' + 'a'.repeat(32);
    ip = () => '1.2.3.4';
    grantCapReached = async () => false;
    grantCapBump = async () => {};
    verifiedInstallOf = () => 'install-1';
  `, f.context)
  const call = async () => {
    f.context.request = new Request('http://localhost/v1/install', {
      method: 'POST',
      headers: { 'x-device-fp': 'a'.repeat(32), 'x-device-id': 'dev-1' },
      body: JSON.stringify({ installId: 'install-1', appVersion: '22' }),
    })
    const res = await vm.runInContext(`(async () => { ${installRoute} })()`, f.context)
    return { status: res.status, body: await res.json() }
  }
  assert.equal((await call()).body.bonus, 50)
  assert.equal((await call()).body.bonus, 0)
  assert.equal(f.env.XDB.sql.prepare('SELECT balance FROM x_guest_wallets').get().balance, 50)
})
