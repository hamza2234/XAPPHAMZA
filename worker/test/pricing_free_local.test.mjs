import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { DatabaseSync } from 'node:sqlite'
import vm from 'node:vm'

// سعر صفر يعني «مجاني» لا «لم يُحدَّد»: كان `|| 1` يرفعه إلى واحد فيُخصم
// من العملات رغم اختيار المالك للمجانية. هذه الاختبارات تثبّت السلوك.
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
  XDB.sql.exec("INSERT INTO x_guest_wallets VALUES ('wallet1', 100, 0, 'test', 'test')")
  const env = { XDB }
  const context = vm.createContext({ Request, Response, URL, TextEncoder, TextDecoder, crypto, console, atob, btoa })
  vm.runInContext(js.replace('export default', 'const worker ='), context)
  vm.runInContext('logSecurity = async () => {}; rateLimit = async () => {};', context)
  context.env = env
  context.caller = { role: 'guest', uid: 'guest1' }
  return { env, context }
}

function charge(f, settings, price) {
  f.context.settings = settings
  f.context.price = price
  const expr = price === undefined
    ? 'chargeOne(env, caller, "wallet1", settings)'
    : 'chargeOne(env, caller, "wallet1", settings, "", false, price)'
  return vm.runInContext(expr, f.context)
}

const balanceOf = (f) =>
  f.env.XDB.sql.prepare("SELECT balance FROM x_guest_wallets WHERE device_id='wallet1'").get().balance

test('compatSearchCost = 0 is free: no coins are deducted', async () => {
  const f = fixture()
  const r = await charge(f, { dailyFreeQuota: 0, compatSearchCost: 0, schemFilePrice: 0 })
  assert.equal(r.source, 'free')
  assert.equal(r.balance, -1)
  assert.equal(balanceOf(f), 100)
})

test('schemFilePrice = 0 is free even when compatSearchCost is positive', async () => {
  const f = fixture()
  const r = await charge(f, { dailyFreeQuota: 0, compatSearchCost: 5, schemFilePrice: 0 }, 0)
  assert.equal(r.source, 'free')
  assert.equal(r.balance, -1)
  assert.equal(balanceOf(f), 100)
})

test('explicit positive schematics price deducts exactly that amount', async () => {
  const f = fixture()
  const r = await charge(f, { dailyFreeQuota: 0, compatSearchCost: 1, schemFilePrice: 3 }, 3)
  assert.equal(r.source, 'coins')
  assert.equal(r.balance, 97)
  assert.equal(balanceOf(f), 97)
})

test('missing price (null) falls back to compatSearchCost, not to free', async () => {
  const f = fixture()
  const r = await charge(f, { dailyFreeQuota: 0, compatSearchCost: 2, schemFilePrice: 9 })
  assert.equal(r.source, 'coins')
  assert.equal(r.balance, 98)
})

test('compatSearchCost = 0 with null price is free', async () => {
  const f = fixture()
  const r = await charge(f, { dailyFreeQuota: 0, compatSearchCost: 0, schemFilePrice: 9 })
  assert.equal(r.source, 'free')
  assert.equal(balanceOf(f), 100)
})

test('owner is always free regardless of price', async () => {
  const f = fixture()
  f.context.caller = { role: 'owner', uid: 'owner1' }
  const r = await charge(f, { dailyFreeQuota: 0, compatSearchCost: 4, schemFilePrice: 4 }, 4)
  assert.equal(r.source, 'owner')
  assert.equal(r.freeLeft, -1)
  assert.equal(balanceOf(f), 100)
})
