import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { DatabaseSync } from 'node:sqlite'
import vm from 'node:vm'

// الشحن الجماعي: إضافة عملات لكل المحافظ أو لنتائج البحث، بلا حلقة على
// الصفوف. هذه الاختبارات تثبّت النطاق (all/q) وأن الرصيد يتراكم لا يُصفّر.
const source = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')
const js = stripTypeScriptTypes(source, { mode: 'transform' })
const schema = readFileSync(new URL('../schema.sql', import.meta.url), 'utf8')

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

function fixture() {
  const XDB = database()
  XDB.sql.exec(schema)
  XDB.sql.exec('CREATE TABLE IF NOT EXISTS x_guest_wallets (device_id TEXT PRIMARY KEY, balance INTEGER, expires_at INTEGER, created_at TEXT, updated_at TEXT)')
  XDB.sql.exec("INSERT INTO x_guest_wallets VALUES ('fp:aaa', 10, 0, 't', 't')")
  XDB.sql.exec("INSERT INTO x_guest_wallets VALUES ('fp:bbb', 0, 0, 't', 't')")
  XDB.sql.exec("INSERT INTO x_guest_wallets VALUES ('fp:ccc', 5, 0, 't', 't')")
  XDB.sql.exec("INSERT INTO x_installs (install_id, device_id, app_version, first_seen, last_seen, last_ip) VALUES ('i1','fp:bbb','22','t','t','9.9.9.9')")
  XDB.sql.exec("INSERT INTO x_users (id, username, display_name, role, device_id, created_at) VALUES ('u1','sara','سارة','user','fp:ccc','t')")
  const env = { XDB }
  const context = vm.createContext({ Request, Response, URL, TextEncoder, TextDecoder, crypto, console, atob, btoa })
  vm.runInContext(js.replace('export default', 'const worker ='), context)
  vm.runInContext(
    "logSecurity = async () => {}; sealed = v => new Response(JSON.stringify(v), { headers: { 'content-type': 'application/json' } });",
    context)
  context.env = env
  const route = js.slice(
    js.indexOf("if (path === '/v1/owner/wallets/bulk'"),
    js.indexOf("if (path === '/v1/owner/bans'"))
  return {
    env, context,
    async bulk(payload) {
      context.path = '/v1/owner/wallets/bulk'
      context.request = new Request('http://localhost/v1/owner/wallets/bulk', {
        method: 'POST', body: JSON.stringify(payload),
      })
      const res = await vm.runInContext(`(async () => { ${route} })()`, context)
      return { status: res.status, body: await res.json() }
    },
  }
}

const bal = (f, id) =>
  f.env.XDB.sql.prepare('SELECT balance FROM x_guest_wallets WHERE device_id=?1').get(id)?.balance

test('all=true adds coins to every wallet and accumulates', async () => {
  const f = fixture()
  const r = await f.bulk({ coins: 50, days: 0, all: true })
  assert.equal(r.status, 200)
  assert.equal(r.body.affected, 3)
  assert.equal(bal(f, 'fp:aaa'), 60)
  assert.equal(bal(f, 'fp:bbb'), 50)
  assert.equal(bal(f, 'fp:ccc'), 55)
})

test('search scope touches only matching wallets', async () => {
  const f = fixture()
  const r = await f.bulk({ coins: 7, days: 0, q: 'fp:bb' })
  assert.equal(r.body.affected, 1)
  assert.equal(bal(f, 'fp:bbb'), 7)
  assert.equal(bal(f, 'fp:aaa'), 10)
  assert.equal(bal(f, 'fp:ccc'), 5)
})

test('search matches by username through the linked user', async () => {
  const f = fixture()
  const r = await f.bulk({ coins: 3, days: 0, q: 'sara' })
  assert.equal(r.body.affected, 1)
  assert.equal(bal(f, 'fp:ccc'), 8)
})

test('search matches by last known IP through installs', async () => {
  const f = fixture()
  const r = await f.bulk({ coins: 4, days: 0, q: '9.9.9.9' })
  assert.equal(r.body.affected, 1)
  assert.equal(bal(f, 'fp:bbb'), 4)
})

test('days sets an expiry in the future', async () => {
  const f = fixture()
  await f.bulk({ coins: 1, days: 30, all: true })
  const exp = f.env.XDB.sql.prepare("SELECT expires_at FROM x_guest_wallets WHERE device_id='fp:aaa'").get().expires_at
  assert.ok(exp > Date.now())
})

test('zero coins is rejected, and missing scope is rejected', async () => {
  const f = fixture()
  await assert.rejects(f.bulk({ coins: 0, all: true }), (e) => e.status === 400)
  await assert.rejects(f.bulk({ coins: 5 }), (e) => e.status === 400)
})
