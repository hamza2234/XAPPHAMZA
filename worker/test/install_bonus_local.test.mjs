// اختبار محلي لمكافأة أول تثبيت (`POST /v1/install`).
//
// لا يلمس الإنتاج: ينفّذ كود المسار مع SQLite في الذاكرة وبديل لواجهة D1،
// بنفس نمط `compat_quota_local.test.mjs`. يغطي السيناريوهات المطلوبة:
// جهاز جديد، إعادة فتح، إعادة تثبيت، بصمة مختلفة عن معرّف الجهاز، غياب
// البصمة، جهازان مستقلان، والقيمة من الإعدادات (50/0).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { DatabaseSync } from 'node:sqlite'
import vm from 'node:vm'

const source = readFileSync(new URL('../src/index.ts', import.meta.url), 'utf8')
const js = stripTypeScriptTypes(source, { mode: 'transform' })
const schema = readFileSync(new URL('../schema.sql', import.meta.url), 'utf8')

function database() {
  const sql = new DatabaseSync(':memory:')
  return {
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
      sql.exec('BEGIN')
      try {
        const out = []
        for (const s of statements) out.push(await s.all())
        sql.exec('COMMIT')
        return out
      } catch (e) { sql.exec('ROLLBACK'); throw e }
    },
  }
}

function fixture({ installBonus = 10, capReached = false } = {}) {
  const XDB = database()
  XDB.sql.exec(schema)
  XDB.sql.exec('CREATE TABLE IF NOT EXISTS x_guest_wallets (device_id TEXT PRIMARY KEY, balance INTEGER, expires_at INTEGER, created_at TEXT, updated_at TEXT)')
  const env = { XDB }
  const context = vm.createContext({ Request, Response, URL, TextEncoder, TextDecoder, crypto, console, atob, btoa })
  vm.runInContext(js.replace('export default', 'const worker ='), context)
  vm.runInContext(
    `logSecurity = async () => {}; rateLimit = async () => {}; ` +
    `grantCapReached = async () => ${capReached}; grantCapBump = async () => {};`,
    context)
  context.env = env
  context.settings = { installBonus }

  const route = (start, end) => js.slice(js.indexOf(start), js.indexOf(end, js.indexOf(start)))
  const installCode = route("if (path === '/v1/install' && request.method === 'POST')", "if (path === '/v1/install/key'")

  return {
    env,
    async install({ installId, deviceId, fp }) {
      // محفظة التثبيت: البصمة إن وُجدت، وإلا معرّف التثبيت (نفس منطق walletOf).
      context.walletOf = async () => (fp ? 'fp:' + fp : 'in:' + installId)
      const headers = { 'content-type': 'application/json' }
      if (installId) headers['x-install-id'] = installId
      if (deviceId) headers['x-device-id'] = deviceId
      if (fp) headers['x-device-fp'] = fp
      context.path = '/v1/install'
      context.request = new Request('http://localhost/v1/install', {
        method: 'POST', headers, body: JSON.stringify({ installId, appVersion: '23' }),
      })
      const res = await vm.runInContext(`(async () => { ${installCode} })()`, context)
      return { status: res.status, body: await res.json() }
    },
    bonusRows: () => XDB.sql.prepare('SELECT * FROM x_install_bonus').all(),
    wallets: () => XDB.sql.prepare('SELECT * FROM x_guest_wallets ORDER BY device_id').all(),
  }
}

const FP1 = 'a1b2c3d4e5f60718'
const FP2 = 'bbbbbbbbbbbbbbbb'

test('جهاز جديد يحصل على المكافأة', async () => {
  const f = fixture({ installBonus: 50 })
  const r = await f.install({ installId: 'inst-1', deviceId: FP1, fp: FP1 })
  assert.equal(r.status, 200)
  assert.equal(r.body.bonus, 50)
  assert.equal(f.bonusRows().length, 1)
  assert.equal(f.wallets()[0].balance, 50)
})

test('إعادة فتح التطبيق لا تمنح مرة ثانية', async () => {
  const f = fixture({ installBonus: 50 })
  await f.install({ installId: 'inst-1', deviceId: FP1, fp: FP1 })
  const r2 = await f.install({ installId: 'inst-1', deviceId: FP1, fp: FP1 })
  assert.equal(r2.body.bonus, 0)
  assert.equal(f.wallets()[0].balance, 50)
})

test('إعادة التثبيت (تثبيت جديد، البصمة نفسها) لا تمنح ثانية', async () => {
  const f = fixture({ installBonus: 50 })
  await f.install({ installId: 'inst-1', deviceId: FP1, fp: FP1 })
  const r2 = await f.install({ installId: 'inst-2', deviceId: FP1, fp: FP1 })
  assert.equal(r2.body.bonus, 0)
  assert.equal(f.bonusRows().length, 1)
})

test('اختلاف البصمة عن معرّف الجهاز لا يمنع المكافأة', async () => {
  const f = fixture({ installBonus: 50 })
  const r = await f.install({ installId: 'inst-1', deviceId: FP1, fp: FP2 })
  assert.equal(r.body.bonus, 50)
  assert.equal(f.bonusRows()[0].fp, 'fp:' + FP2)
})

test('غياب ترويسة البصمة لا يمنع المكافأة (تُقرأ من معرّف الجهاز)', async () => {
  const f = fixture({ installBonus: 50 })
  const r = await f.install({ installId: 'inst-1', deviceId: FP1 })
  assert.equal(r.body.bonus, 50)
  assert.equal(f.bonusRows()[0].fp, 'fp:' + FP1)
})

test('جهازان مختلفان يحصلان على مكافأة مستقلة', async () => {
  const f = fixture({ installBonus: 50 })
  const r1 = await f.install({ installId: 'inst-1', deviceId: FP1, fp: FP1 })
  const r2 = await f.install({ installId: 'inst-2', deviceId: FP2, fp: FP2 })
  assert.equal(r1.body.bonus, 50)
  assert.equal(r2.body.bonus, 50)
  assert.equal(f.bonusRows().length, 2)
})

test('installBonus = 0 تعطّل المنح', async () => {
  const f = fixture({ installBonus: 0 })
  const r = await f.install({ installId: 'inst-1', deviceId: FP1, fp: FP1 })
  assert.equal(r.body.bonus, 0)
  assert.equal(f.bonusRows().length, 0)
})

test('سقف العنوان يمنع المنح بلا رفض الطلب', async () => {
  const f = fixture({ installBonus: 50, capReached: true })
  const r = await f.install({ installId: 'inst-cap', deviceId: FP1, fp: FP1 })
  assert.equal(r.status, 200)
  assert.equal(r.body.bonus, 0)
  assert.equal(f.bonusRows().length, 0)
})
