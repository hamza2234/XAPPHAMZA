/**
 * x-app-api — الواجهة الخلفية الآمنة لتطبيق X
 *
 * مبادئ العزل:
 *  - MIRROR (phonex-mirror) و SCHEMATICS (phonex-schematics): قراءة فقط.
 *    لا يوجد أي استدعاء put/delete على هذه الموارد في هذا الملف.
 *  - XDB (x-app-db) و QUOTA (x-app-quota): ملك تطبيق X وحده.
 *
 * طبقات الأمان:
 *  1) حظر أدوات السكريبت (User-Agent)
 *  2) تصعيد حظر IP عند تكرار الطلبات الفاشلة
 *  3) توقيع HMAC لكل طلب (X-App-Ts + X-App-Sig) — بدونه يُرفض الطلب
 *  4) JWT للجلسات + ربط الحساب بجهاز واحد
 *  5) كشف مزارع الأجهزة (IP واحد بأجهزة كثيرة)
 *  6) سجل أحداث أمنية (جهاز + IP + مسار + سبب) يطلع عليه المالك
 *  7) حصة يومية للزائر على فتح ملفات المخططات — يتحكم بها المالك
 *  8) بوابة إصدارات: إيقاف الإصدارات القديمة من لوحة المالك
 */

// ============================== Crypto ==============================

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message)
  }
}

/**
 * مفتاح تشفير ردود لوحة المالك، مشتق من جلسة المالك نفسها.
 *
 * الغرض: لو تسرّبت استجابة لوحة المالك (سجل وسيط، نسخة احتياطية، كاش)
 * يبقى محتواها غير مقروء. لماذا من الجلسة وليس من سرّ ثابت؟ لأن أي سرّ
 * ثابت يجب أن يُضمَّن في التطبيق ليتمكن من الفك، فيصبح مكشوفاً لأي من
 * يفكّ الـAPK. الجلسة وحدها يملكها المالك، وتنتهي بانتهائها.
 *
 * هذا يحمي المحتوى أثناء النقل والتخزين، ولا يغني عن TLS: من يقرأ
 * الترويسات يقرأ الجلسة، لكنه لا يقرأ الأجسام من السجلات أو النسخ.
 */
async function ownerCipherKey(token: string): Promise<CryptoKey> {
  const material = await crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode(`xapp-owner-panel-v1|${token}`)
  )
  return crypto.subtle.importKey('raw', material, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

/** يشفّر رد لوحة المالك: AES-GCM مع nonce عشوائي لكل استجابة. */
async function ownerSeal(token: string, payload: unknown): Promise<string> {
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const key = await ownerCipherKey(token)
  const plain = new TextEncoder().encode(JSON.stringify(payload))
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, plain)
  return `${b64e(nonce)}.${b64e(cipher)}`
}

/** يفكّ ما شفّره ownerSeal — يُستخدم في الاختبارات والتحقق. */
async function ownerOpen(token: string, sealed: string): Promise<unknown> {
  const [n, c] = sealed.split('.')
  const key = await ownerCipherKey(token)
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64d(n) }, key, b64d(c)
  )
  return JSON.parse(new TextDecoder().decode(plain))
}

function b64e(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function b64d(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (str.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  )
}

async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await hmacKey(secret)
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message))
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('')
}

async function signJwt(payload: Record<string, unknown>, secret: string, ttlSeconds: number): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const data = `${b64e(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })))}.${b64e(new TextEncoder().encode(JSON.stringify({ ...payload, iat: now, exp: now + ttlSeconds })))}`
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), new TextEncoder().encode(data))
  return `${data}.${b64e(sig)}`
}

async function verifyJwt(token: string, secret: string): Promise<Record<string, any>> {
  const parts = token.split('.')
  if (parts.length !== 3) throw new HttpError(401, 'invalid token')
  const data = `${parts[0]}.${parts[1]}`
  const valid = await crypto.subtle.verify('HMAC', await hmacKey(secret), b64d(parts[2]), new TextEncoder().encode(data))
  if (!valid) throw new HttpError(401, 'invalid token')
  const payload = JSON.parse(new TextDecoder().decode(b64d(parts[1])))
  if (typeof payload.exp === 'number' && payload.exp < Math.floor(Date.now() / 1000)) {
    throw new HttpError(401, 'token expired')
  }
  return payload
}

async function pbkdf2(password: string, salt: Uint8Array): Promise<string> {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, base, 256)
  return b64e(bits)
}

async function hashPassword(password: string): Promise<string> {
  const salt = new Uint8Array(16)
  crypto.getRandomValues(salt)
  return `pbkdf2$100000$${b64e(salt)}$${await pbkdf2(password, salt)}`
}

async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$')
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false
  return (await pbkdf2(password, b64d(parts[2]))) === parts[3]
}

// ============================== Helpers ==============================

interface Env {
  MIRROR: D1Database
  XDB: D1Database
  QUOTA: KVNamespace
  SCHEMATICS: R2Bucket
  XMEDIA: R2Bucket
  XLEARN: R2Bucket
  RELEASES: R2Bucket
  X_JWT_SECRET: string
  X_SIG_SECRET: string
  X_OWNER_KEY: string
  X_OWNER_JWT_SECRET?: string
  /**
   * مفتاح تشفير فيديوهات الدورات — لم يُعد مستعملاً.
   *
   * كان الفيديو يُشفّر بمفتاح مستقل، ثم صار التشفير كله على مستوى التطبيق
   * بمفتاح واحد مضمّن. وقد أُزيل ذلك أيضاً: المفتاح المضمّن في كل نسخة ليس
   * عزلاً، فمن استخرجه فكّ كل ملف. العزل الحقيقي يأتي من دلو XLEARN
   * المستقل ومن حصر الوصول بتوقيع موثّق؛ أُبقي الحقل اختيارياً كي لا يفشل
   * نشر قائم يشير إليه.
   */
  X_LEARN_KEY?: string
  /**
   * مفتاح تشفير الملفات القديم — لم يبقَ له مستعمل.
   *
   * أُزيل مع دوال `fileCryptoKey`/`fileNonce`. إبقاء الحقل اختياريّاً كي لا
   * يفشل نشر قائم يشير إليه، ولا يُقرأ في أي مسار.
   */
  X_FILE_KEY?: string
  /** حساب خدمة Firebase (JSON كامل) — إن غاب، الدفع معطّل بهدوء. */
  FCM_SERVICE_ACCOUNT?: string
  /** معرّف مشروع Firebase — يُقرأ من الحساب إن لم يُضبط هنا. */
  FCM_PROJECT_ID?: string
}

interface Caller { uid: string; role: string }

const DAY = 86400
const FOLDER_MIME = 'application/vnd.google-apps.folder'
const LOCAL_PREFIX = 'local:'
const LOCAL_R2 = 'local/'
const ROOT_CATALOG = 'catalog/v1/brands.json'

// 8MiB لا 4: R2 يرفض كل جزء أصغر من 5MiB (آخر جزء وحده مستثنى)، فالرفع
// بـ4MiB كان يفشل على أي مقطع يتجاوز جزءاً واحداً — أي كل فيديو فوق 4MiB،
// وهو حدّ الفشل الذي ظهر كأنه «تقييد على الرفع». و8MiB تبقى تحت حدّ حافة
// العامل بهامش مريح مع ترويسات الطلب.
const CHAT_UPLOAD_CHUNK = 8 * 1024 * 1024

const BLOCKED_UA = /(curl|wget|python-requests|python-urllib|scrapy|go-http-client|libwww|node-fetch|axios\/|postmanruntime|httpie)|^\s*$|bot|spider|crawler/i

function json(body: unknown, status = 200, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...extra }
  })
}

function ip(request: Request): string {
  return request.headers.get('cf-connecting-ip')?.trim() || 'unknown'
}

function deviceOf(request: Request): string {
  return request.headers.get('x-device-id')?.trim() ?? ''
}

function versionOf(request: Request): number {
  return Number(request.headers.get('x-app-version')?.trim() || '0') || 0
}

function today(): string {
  return new Date().toISOString().slice(0, 10)
}

function uid(): string {
  return `${Date.now().toString(36)}_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`
}

// ============================== X DB helpers ==============================

interface XUser {
  id: string; username: string; display_name: string; role: string
  quota_balance: number; quota_expires_at: number
  active: number; device_id: string | null; expires_at: number
}

async function xUser(XDB: D1Database, id: string): Promise<XUser | null> {
  return XDB.prepare('SELECT * FROM x_users WHERE id = ?1').bind(id).first<XUser>()
}

async function xUserByName(XDB: D1Database, username: string): Promise<XUser | null> {
  return XDB.prepare('SELECT * FROM x_users WHERE username = ?1 COLLATE NOCASE').bind(username).first<XUser>()
}

interface XSettings {
  dailyFreeQuota: number          // المنحة اليومية الواحدة لكل مستخدم (زائر أو مسجل أو مشترك)
  guestFileQuota: number          // مهجور: يُعاد كتابته من dailyFreeQuota للتوافق مع النسخ القديمة
  minVersion: number              // أدنى إصدار مسموح
  blockedVersions: number[]       // إصدارات موقوفة تحديداً
  telegramLink: string
  schematicsLocked: boolean       // قفل المخططات كلياً عن الزوار
  compatLocked: boolean           // قفل التوافقات عن الزوار
  compatSearchCost: number        // ثمن دخول الشركة في التوافقات بالعملات (0 = مجاني)
  schemFilePrice: number          // ثمن فتح ملف مخطط بالعملات (0 = يعتمد المنحة فقط)
  dailyGiftAmount: number         // عملات الهديّة اليومية التي يمنحها زر الهديّة (0 = معطّل)
  installBonus: number            // عملات مكافأة أول تثبيت على الجهاز (0 = معطّلة)
  videosHidden: boolean           // إيقاف عرض الفيديوهات فوراً للجميع (مفتاح المالك)
  videosHiddenMessage: string     // ما يُعرض للمستخدم حين يكون العرض موقوفاً
  guestCompatQuota: number        // مهجور: كان حصة مستقلة للتوافقات، صار نسخة من dailyFreeQuota
  appLocked: boolean              // قفل التطبيق كلياً (صيانة)
  lockMessage: string
  updateMessage: string           // رسالة شاشة التحديث الإجباري
  updateUrl: string               // رابط زر التحديث
  updateImageUrl: string          // صورة شاشة التحديث
  packages: { cards: number; price: string; days: number; desc: string }[]  // باقات العملات
  privacyPolicy: string           // سياسة الخصوصية — يكتبها المالك وتظهر للمستخدم
  // ── الدردشة المجتمعية ──
  chatEnabled: boolean            // تشغيل/إيقاف الدردشة كلياً
  chatReadOnly: boolean           // وضع القراءة فقط: تُقرأ الرسائل ولا تُكتب
  chatRooms: { id: string; name: string; icon: string }[]  // أقسام الدردشة
  chatTheme: string               // سمة الدردشة: classic | bubble | dark | neon
  chatWelcome: string             // رسالة نظام تُعرض عند دخول أي قسم
  chatMaxLength: number           // أقصى طول للرسالة النصية
  chatImagesEnabled: boolean      // السماح برفع الصور في الدردشة
  chatWriteScope: string          // من يكتب: all | registered | subscribers
  chatMediaScope: string          // من يرسل صوت/فيديو: subscribers | none
  chatMaxMediaMb: number          // أقصى حجم للمقطع الصوتي/المرئي بالميغابايت
  chatMediaSeconds: number        // أقصى مدة للمقطع بالثواني
  chatPollMs: number              // دور تحديث الدردشة في التطبيق (مللي ثانية)
}

const DEFAULT_SETTINGS: XSettings = {
  dailyFreeQuota: 5,
  guestFileQuota: 5,
  minVersion: 1,
  blockedVersions: [],
  telegramLink: 'https://t.me/phonex6',
  schematicsLocked: false,
  compatLocked: false,
  compatSearchCost: 1,
  schemFilePrice: 1,
  dailyGiftAmount: 5,
  installBonus: 10,
  videosHidden: false,
  videosHiddenMessage: 'الفيديوهات متوقفة مؤقتاً — سنعاود قريباً',
  guestCompatQuota: 5,
  appLocked: false,
  lockMessage: '',
  updateMessage: 'يتوفر إصدار جديد — حدّث التطبيق للمتابعة',
  updateUrl: '',
  updateImageUrl: '',
  packages: [
    { cards: 150, price: '3$', days: 60, desc: 'صالحة لغاية شهرين' },
    { cards: 300, price: '5$', days: 150, desc: 'صالحة لغاية 5 أشهر' },
    { cards: 500, price: '7$', days: 365, desc: 'صالحة لغاية سنة كاملة' },
  ],
  // نص افتراضي مفهوم بلغة واضحة. المالك يستبدله من لوحته، ووجوده هنا يضمن
  // ألا يظهر للمستخدم صندوق فارغ إن لم يكتب المالك نصاً بعد.
  privacyPolicy: `نحن في PhoneX نحترم خصوصيتك ونوضح لك بلغة بسيطة ما نجمعه ولماذا.
ما نجمعه:
• معرّف الجهاز: رقم مشتق من جهازك، نستخدمه لربط حسابك بجهازك ومنحك حصتك اليومية. لا يمكن من خلاله معرفة هويتك.
• عنوان الإنترنت (IP): نستخدمه لحماية التطبيق من الهجمات والاستخدام الآلي المسيء.
• اسم المستخدم وكلمة المرور: كلمة المرور تُخزَّن مشفّرة، ولا يمكن لأحد — بمن فيهم نحن — قراءتها.

ما لا نجمعه:
• لا نصل إلى جهات الاتصال أو الصور أو الرسائل أو الموقع الجغرافي.
• لا نبيع بياناتك ولا نشاركها مع أي طرف ثالث لأغراض تجارية.

كيف تُستخدم بياناتك:
• لتشغيل حسابك وحفظ رصيدك وحصتك اليومية.
• لحماية التطبيق من العبث والهجمات.

الاحتفاظ والحذف:
• تبقى بياناتك ما دام حسابك قائماً. يمكنك طلب حذف حسابك وبياناتك في أي وقت عبر التواصل مع المالك.

المسؤولية:
• أنت مسؤول عن سرّية كلمة مرورك. لا تشارك حسابك مع الآخرين.

بالمتابعة أنت توافق على هذه السياسة.`,

  // ── الدردشة: مفعّلة بأقسام جاهزة، والمالك يعدّلها من لوحته ──
  chatEnabled: true,
  chatReadOnly: false,
  chatRooms: [
    { id: 'general', name: 'العامة', icon: 'chat' },
    { id: 'help', name: 'مساعدة وإصلاح', icon: 'build' },
    { id: 'parts', name: 'قطع وموديلات', icon: 'memory' },
    { id: 'offers', name: 'عروض وتجار', icon: 'store' },
  ],
  chatTheme: 'bubble',
  chatWelcome: 'أهلاً بك — التزم بالأدب ولا تشارك بياناتك الخاصة مع أحد.',
  chatMaxLength: 1000,
  chatImagesEnabled: true,
  // الكتابة للمسجّلين، والصوت/الفيديو للمشتركين السارين فقط. الافتراضي
  // الأكثر تقييداً حتى يقرر المالك خلافه.
  chatWriteScope: 'registered',
  chatMediaScope: 'subscribers',
  chatMaxMediaMb: 200,
  chatMediaSeconds: 120,
  chatPollMs: 4000,
}

async function xSettings(XDB: D1Database): Promise<XSettings> {
  const row = await XDB.prepare("SELECT data FROM x_settings WHERE id = 'main'").first<{ data: string }>()
  if (!row) return { ...DEFAULT_SETTINGS }
  try {
    const raw = JSON.parse(row.data) as Partial<XSettings>
    return normalizeSettings({ ...DEFAULT_SETTINGS, ...raw }, raw)
  } catch { return { ...DEFAULT_SETTINGS } }
}

/**
 * المنحة اليومية صارت واحدة لكل المستخدمين، وكانت منفصلة: حصة للملفات
 * وحصة للتوافقات. صفّ قديم بلا الحقل الجديد يحمل الرقمين، وأخذ أحدهما فقط
 * يغيّر ما اعتاده المالك — نأخذ الأكبر. أما 0 فيبقى 0: إلغاء المنحة قرار
 * صريح من المالك لا يُستبدل بالافتراضي.
 */
function normalizeSettings(s: XSettings, raw: Partial<XSettings>): XSettings {
  if (raw.dailyFreeQuota === undefined) {
    const legacy = Math.max(Number(raw.guestFileQuota) || 0, Number(raw.guestCompatQuota) || 0)
    if (legacy > 0) s.dailyFreeQuota = Math.min(1000, legacy)
  }
  s.dailyFreeQuota = Math.max(0, Math.min(1000, Math.floor(Number(s.dailyFreeQuota) || 0)))
  s.dailyGiftAmount = s.dailyFreeQuota
  s.videosHidden = !!s.videosHidden
  // الحقلان المهجوران يبقيان معروضين في bootstrap بنفس القيمة كي لا تظن
  // نسخة قديمة من التطبيق أن المالك ألغى المنحة.
  s.guestFileQuota = s.dailyFreeQuota
  s.guestCompatQuota = s.dailyFreeQuota

  // أقسام الدردشة: نُبقي معرّفات صالحة فقط، ونمنع التكرار — معرّف مكرر كان
  // سيجمع رسائل قسمين في قسم واحد بلا أن يظهر خطأ للمالك.
  const seen = new Set<string>()
  const rooms = (Array.isArray(s.chatRooms) ? s.chatRooms : [])
    .map(r => ({
      id: String(r?.id ?? '').trim().toLowerCase().replace(/[^\w-]/g, '').slice(0, 24),
      name: String(r?.name ?? '').trim().slice(0, 40),
      icon: String(r?.icon ?? 'chat').trim().replace(/[^\w]/g, '').slice(0, 16) || 'chat',
    }))
    .filter(r => r.id && r.name && !seen.has(r.id) && (seen.add(r.id), true))
  // قسم واحد على الأقل: دردشة بلا قسم لا يمكن استخدامها.
  s.chatRooms = rooms.length ? rooms.slice(0, 20)
    : [{ id: 'general', name: 'العامة', icon: 'chat' }]
  if (!['classic', 'bubble', 'dark', 'neon'].includes(s.chatTheme)) s.chatTheme = 'bubble'
  s.chatMaxLength = Math.max(80, Math.min(4000, Math.floor(Number(s.chatMaxLength) || 1000)))
  s.chatWelcome = String(s.chatWelcome ?? '').slice(0, 300)
  if (!['all', 'registered', 'subscribers'].includes(s.chatWriteScope)) s.chatWriteScope = 'registered'
  if (!['subscribers', 'none'].includes(s.chatMediaScope)) s.chatMediaScope = 'subscribers'
  // الحدّ الأعلى 200MB لا 25: الرفع على أجزاء داخل R2 فلا سقف تقني عند 25
  // (سقف R2 نفسه 5TiB و10,000 جزء)، و25 كانت تكفي مقطعاً قصيراً فقط. يبقى
  // حدّاً يمنع تحويل الدلو إلى مزبلة ملفات ويراعي بيانات مستخدمي الجوال.
  s.chatMaxMediaMb = Math.max(25, Math.min(200, Math.floor(Number(s.chatMaxMediaMb) || 200)))
  s.chatMediaSeconds = Math.max(5, Math.min(300, Math.floor(Number(s.chatMediaSeconds) || 120)))
  // دور التحديث: أقل من ثانيتين يرهق الخادم، وأكثر من 30 يعني دردشة بطيئة.
  s.chatPollMs = Math.max(2000, Math.min(30000, Math.floor(Number(s.chatPollMs) || 4000)))
  return s
}

async function logSecurity(env: Env, request: Request, reason: string, detail = ''): Promise<void> {
  try {
    await env.XDB.prepare(
      'INSERT INTO x_security (device_id, ip, path, reason, detail, at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)'
    ).bind(
      deviceOf(request) || null, ip(request), new URL(request.url).pathname,
      reason, detail.slice(0, 300), new Date().toISOString()
    ).run()
  } catch { /* السجل لا يُسقط الطلب */ }
}

// ============================== Security layer ==============================

/**
 * عدّ الإساءة. `severity` يفصل الخطأ البشري عن محاولات التجاوز:
 * كلمة مرور خاطئة متكررة تعني مستخدماً نسِي كلمته، لا مهاجماً — وكانت
 * 15 محاولة كافية لحظر جهازه نهائياً. الخطر الحقيقي (توقيع مزوّر) وحده
 * يستحق الحظر التلقائي.
 */
async function noteAbuse(env: Env, request: Request, reason: string, severity: 'low' | 'high' = 'high'): Promise<void> {
  const addr = ip(request)
  if (severity === 'low') return
  try {
    // عدّاد إساءة للجهاز أيضاً — تغيير IP/البروكسي لا يحمي المتلاعب
    const dev = deviceOf(request)
    if (dev) {
      const dk = `abusedev:${dev}`
      const dc = Number(await env.QUOTA.get(dk)) || 0
      await env.QUOTA.put(dk, String(dc + 1), { expirationTtl: 3600 })
      // 15 إساءة كانت تكفي لحظر جهاز نهائياً. هذا الرقم يبلغه إنسان
      // بسهولة: تحديث سريع للتطبيق، أو بقاء الشاشة مفتوحة على شبكة
      // تتقطّع، أو جهاز يرسل طلبه مرتين. الحظر النهائي للجهاز صار 40،
      // وهو رقم لا يصله إلا من يعيد المحاولة آلياً بعد الرفض.
      if (dc + 1 >= 40) {
        await banDevice(env, dev, `auto:${reason}`, request)
      }
    }
    if (addr !== 'unknown') {
      const key = `abuse:${addr}`
      const count = Number(await env.QUOTA.get(key)) || 0
      await env.QUOTA.put(key, String(count + 1), { expirationTtl: 600 })
      // الحظر بعد 20 إساءة كان يضرب عناوين CGNAT المشتركة: جهاز واحد مسيء
      // يحجب جيرانه كلهم. صار التسجيل أولاً، والحظر عند 60 إساءة في نفس
      // النافذة القصيرة — رقم لا يبلغه مستخدم شرعي.
      // حظر العنوان أوسع أثراً من حظر الجهاز: مشغّلو الجوال يضعون آلاف
      // المستخدمين خلف عنوان واحد، فحظره يعاقب من لم يذنب. صار 200 إساءة
      // في النافذة القصيرة — رقم آلي بحت.
      if (count + 1 >= 200) {
        await env.QUOTA.put(`hardban:${addr}`, 'repeat', { expirationTtl: 3600 })
        await logSecurity(env, request, 'ip_hardban', `reason=${reason} strikes=${count + 1}`)
      }
    }
  } catch { /* ignore */ }
}

/** حظر جهاز نهائي — لا يفيده تغيير IP أو بروكسي أو حساب جديد */
/**
 * حظر IP دائم — يُستخدم مع حظر الجهاز: الأول يوقف المهاجم فوراً،
 * والثاني يمنعه حتى لو غيّر عنوانه.
 */
async function banIp(env: Env, addr: string, reason: string, request?: Request): Promise<void> {
  await env.QUOTA.put(`hardban:${addr}`, 'perm') // بلا انتهاء
  await env.XDB.prepare(
    `INSERT INTO x_bans (id, kind, reason, permanent, at) VALUES (?1, 'ip', ?2, 1, ?3)
     ON CONFLICT(id) DO UPDATE SET reason = ?2, at = ?3`
  ).bind(addr, reason.slice(0, 200), new Date().toISOString()).run()
  if (request) await logSecurity(env, request, 'ip_banned', reason)
}

async function banDevice(env: Env, deviceId: string, reason: string, request?: Request): Promise<void> {
  await env.QUOTA.put(`devban:${deviceId}`, 'perm') // بلا انتهاء
  await env.XDB.prepare(
    `INSERT INTO x_bans (id, kind, reason, permanent, at) VALUES (?1, 'device', ?2, 1, ?3)
     ON CONFLICT(id) DO NOTHING`
  ).bind(deviceId, reason, new Date().toISOString()).run()
  if (request) await logSecurity(env, request, 'device_banned', reason)
}

/**
 * حدّ الانفجار: نافذة ثانية واحدة.
 *
 * كل الحدود الأخرى نوافذها دقائق، فالعدّاد يسمح بسحب الحدّ كاملاً في جزء من
 * الثانية: 240 بحثاً في 600 ثانية تعني عملياً «بلا حدّ» لمن يكتب حلقة.
 * هذا الحدّ يقيس المعدّل اللحظي فيوقف الآلة دون أن يلمس المستخدم الذي
 * يفتح ملفاً أو يبحث بيده — الحدّ 8 أضعاف أسرع استعمال بشري.
 */
async function burstLimit(env: Env, request: Request, bucket: string, max: number): Promise<void> {
  const dev = deviceOf(request)
  const who = dev || `ip:${ip(request)}`
  const slot = Math.floor(Date.now() / 1000)
  const key = `burst:${bucket}:${who}:${slot}`
  const used = Number(await kvGet(env, key)) || 0
  if (used + 1 > max) {
    if (await hasOwnerSession(env, request)) return
    await logSecurity(env, request, 'burst_limited', `bucket=${bucket} max=${max}/s`)
    // لا يُحتسب الانفجار إساءةً خطيرة: عاصفة إعادة المحاولة بعد انقطاع شبكة
    // ترسل عشرات الطلبات في ثانية، وهي سلوك جهاز شرعي لا مهاجم. كانت
    // تُحتسب «high» فتبلغ 15 إساءة وتحظر الجهاز نهائياً.
    await noteAbuse(env, request, `burst:${bucket}`, 'low')
    throw new HttpError(429, RATE_LIMIT_MSG)
  }
  try {
    // ثانيتان تكفيان: المفتاح مُرقّم بالثانية ولا يُقرأ بعده.
    await env.QUOTA.put(key, String(used + 1), { expirationTtl: 2 })
  } catch { /* تعذّر العدّ لا يُسقط الطلب */ }
}

/**
 * كشف السحب المنهجي: عدد عناصر مختلفة يطلبها المصدر نفسه في نافذة.
 *
 * حدّ المعدّل يقيس الطلبات، وهذا يقيس *تنوّعها*. الفرق جوهري: من يفتح
 * مخططاً ويرجع إليه يكرّر العنوان نفسه فلا يُحتسب، أما من يدور على كل
 * الشركات أو على كل معرّفات الملفات فيُحتسب ولو كان بطيئاً تحت الحدّ.
 * ويُحتسب النجاح وحده — الطلبات الفاشلة ليست سحباً.
 */
async function detectSweep(
  env: Env, request: Request, bucket: string, item: string, max: number, window = 600
): Promise<void> {
  const dev = deviceOf(request)
  const who = dev || `ip:${ip(request)}`
  const key = `sweep:${bucket}:${who}`
  const seen = ((await env.QUOTA.get(key, 'json')) as string[] | null) ?? []
  if (seen.includes(item)) return
  seen.push(item)
  if (seen.length > max) {
    if (await hasOwnerSession(env, request)) return
    await logSecurity(env, request, 'scraping_suspected',
      `bucket=${bucket} distinct=${seen.length}/${max} dev=${dev || '-'}`)
    await noteAbuse(env, request, `sweep:${bucket}`, 'low')
    throw new HttpError(429, RATE_LIMIT_MSG)
  }
  try {
    await env.QUOTA.put(key, JSON.stringify(seen.slice(-max * 2)), { expirationTtl: window })
  } catch { /* ignore */ }
}

/**
 * قراءة من KV لا تُسقط الطلب عند تعطّل KV.
 *
 * كانت أي مشكلة مؤقتة في KV تُفشل كل طلب قبل وصوله للخادم، فيرى المستخدم
 * «تعذر الاتصال» وهو متصل. فقدان فحص الحظر لدقائق أهون من تعطيل التطبيق كله.
 */
async function kvGet(env: Env, key: string): Promise<string | null> {
  try {
    return await env.QUOTA.get(key)
  } catch {
    return null
  }
}

async function assertDeviceAllowed(env: Env, request: Request): Promise<void> {
  const dev = deviceOf(request)
  if (!dev) return
  if (await kvGet(env, `devban:${dev}`)) {
    if (await hasOwnerSession(env, request)) return
    await logSecurity(env, request, 'banned_device_hit')
    throw new HttpError(403, 'تم حظر هذا الجهاز نهائياً — تواصل مع الدعم')
  }
}

async function assertIpClean(env: Env, request: Request): Promise<void> {
  const addr = ip(request)
  if (await kvGet(env, `hardban:${addr}`)) {
    if (await hasOwnerSession(env, request)) return
    await logSecurity(env, request, 'banned_ip_hit')
    throw new HttpError(403, 'تم حظر هذا العنوان — تواصل مع الدعم')
  }
  if (Number(await kvGet(env, `abuse:${addr}`)) >= 20) {
    if (await hasOwnerSession(env, request)) return
    throw new HttpError(403, 'تم حظر هذا الطلب مؤقتاً')
  }
}

/**
 * هل يحمل الطلب جلسة مالك صالحة؟
 *
 * بدون هذا الاستثناء يبقى المالك خارج التطبيق نهائياً إذا حُظر جهازه أو
 * عنوانه (بنقرة خاطئة على زر الحظر، أو حظر تلقائي بسبب أخطاء اختبار):
 * لا يستطيع الوصول إلى صفحة إلغاء الحظر لأن فحص الحظر يسبق المصادقة.
 * الجلسة تُوقَّع بـ X_JWT_SECRET فلا يمكن تزويرها.
 */
async function hasOwnerSession(env: Env, request: Request): Promise<boolean> {
  const token = request.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim()
  if (!token) return false
  try {
    const payload = await verifyJwt(token, env.X_JWT_SECRET)
    return payload.role === 'owner'
  } catch {
    return false
  }
}

/**
 * حدّ المعدل مفتاحه الجهاز لا العنوان.
 *
 * مشغّلو الجوال يستخدمون CGNAT: آلاف المستخدمين بلا علاقة بينهم يظهرون
 * بالعنوان نفسه. حدّ لكل عنوان كان يعني أن آخر من يفتح التطبيق من ذلك
 * العنوان يُرفض بـ 429 في أول تشغيل، ويُعرض له «تعذر الاتصال». الحدّ لكل
 * جهاز يمنع الجهاز المسيء دون معاقبة جيرانه.
 *
 * العناوين بلا معرّف جهاز (أدوات آلية غالباً) تبقى على الحدّ بالعنوان.
 */
/**
 * رسالة تجاوز الحدّ.
 *
 * لا تقول «حظر» ولا «تم إيقافك»: من بلغ الحدّ في الغالب مستخدم يكتب بسرعة
 * أو شبكته تتقطّع فتعيد الطلب، وقد يكون طفل بضغطة متكرّرة. الرسالة تطلب
 * التمهّل ولا تتّهم.
 */
const RATE_LIMIT_MSG = 'طلبات كثيرة في وقت قصير — انتظر قليلاً ثم تابع'

async function rateLimit(env: Env, request: Request, bucket: string, limit: number, window: number): Promise<void> {
  const dev = deviceOf(request)
  const key = dev ? `rl:${bucket}:d:${dev}` : `rl:${bucket}:ip:${ip(request)}`
  const used = Number(await kvGet(env, key)) || 0
  if (used + 1 > limit) {
    // المالك لا يُحظر بحدّ تلقائي. جلسة المالك موقّعة بـX_JWT_SECRET فلا
    // تُزوَّر، والفحص لا يُنفَّذ إلا عند بلوغ الحدّ — أي أنه لا يُكلّف شيئاً
    // في المسار الطبيعي. هذا يمنع سيناريو أن يغلق المالك نفسه خارج تطبيقه
    // باستعمال كثيف مشروع.
    if (await hasOwnerSession(env, request)) return
    // لا يُحتسب تجاوز الحدّ في رصيد الإساءة: مستخدم شرعي على عنوان مشترك
    // قد يبلغه بسهولة، واحتسابه كان يحوّله إلى حظر كامل بعد 20 مرة.
    await logSecurity(env, request, 'rate_limited', `bucket=${bucket} limit=${limit}/${window}s`)
    // تجاوز الحدّ مضاعفاً عدة مرات نمط آلي، ويُسجَّل ليراه المالك. لا
    // يُحظر شيء هنا: التمييز بين إنسان سريع وسكربت يحتاج بيانات، ولوح
    // المالك هي موضع القرار لا حظر تلقائي أعمى.
    if (used + 1 > limit * 8) {
      await logSecurity(env, request, 'rate_limited_hard',
        `bucket=${bucket} used=${used + 1} limit=${limit}/${window}s`)
    }
    // صياغة إنسانية بلا كلمة «حظر»: من بلغ الحدّ غالباً مستخدم سريع أو
    // شبكة تتقطّع، وإخباره أنه «محظور» يُشعره بأنه متّهم وهو لم يفعل شيئاً.
    throw new HttpError(429, RATE_LIMIT_MSG)
  }
  try {
    await env.QUOTA.put(key, String(used + 1), { expirationTtl: window })
  } catch {
    // تعذّر العدّ لا يمنع الطلب — الحدّ الحقيقي يُفرض عند الخصم من الرصيد.
  }
  // السقف الثاني على العنوان، أوسع بعشر مرات. التوقيع يُحسب على معرّف
  // يرسله العميل، فمن استخرج السرّ يبدّل المعرّف ويبدأ العدّ من صفر؛
  // السقف الواسع يوقف التدوير المتسارع دون أن يعاقب عنواناً مشتركاً.
  if (!dev) return
  const ipKey = `rl:${bucket}:ip:${ip(request)}`
  const ipUsed = Number(await kvGet(env, ipKey)) || 0
  if (ipUsed + 1 > limit * 10) {
    await logSecurity(env, request, 'rate_limited_ip', `bucket=${bucket} limit=${limit * 10}/${window}s`)
    throw new HttpError(429, RATE_LIMIT_MSG)
  }
  try {
    await env.QUOTA.put(ipKey, String(ipUsed + 1), { expirationTtl: window })
  } catch { /* كما أعلاه */ }
}

/**
 * هوية الطلب الموثّقة — تُملأ في `verifySignature` وحده.
 *
 * لماذا WeakMap لا ترويسة: `x-device-id` و`x-device-fp` يرسلهما العميل،
 * ولا تدخلان في نصّ التوقيع (`installId|ts|nonce|method|path|bodyHash`).
 * فمن سجّل مفتاح تثبيت لنفسه — وهو مجاني ولا يحتاج كلمة مرور — يستطيع
 * توقيع طلب صحيح ثم وضع معرّف جهاز المالك فيه. التوقيع يمرّ، و`ownerDevice`
 * كانت تعيد true، فيُفتح كل مقفل بلا كلمة مرور. وهذا هو الانتحال كاملاً:
 * السلطة كانت تُشتقّ من قيمة يملك العميل تغييرها.
 *
 * الحلّ: السلطة تُشتقّ من `installId` وحده، لأنه القيمة الوحيدة التي
 * يثبتها التوقيع بمفتاح خاص لا يغادر الجهاز. الهوية تُحسب مرة في
 * `verifySignature` وتُقرأ هنا في المسارات، فلا تُقرأ ترويسة للسلطة أبداً.
 *
 * لماذا WeakMap: مربوطة بكائن الطلب نفسه، فلا تتسرّب بين الطلبات ولا
 * تحتاج تنظيفاً، ولا يستطيع مسار لاحق تزوير هوية طلب آخر.
 */
const verifiedInstall = new WeakMap<Request, string>()

/** معرّف التثبيت الموثّق لهذا الطلب، أو '' إن لم يُوقَّع بعد. */
function verifiedInstallOf(request: Request): string {
  return verifiedInstall.get(request) ?? ''
}

/** توقيع التطبيق: Ed25519 لكل تثبيت — `X-App-Sig` على
 *  `installId|ts|nonce|method|path+query|bodyHash`، بمفتاح عام مسجَّل مسبقاً. */
async function verifySignature(env: Env, request: Request): Promise<void> {
  // المفتاح العام لكل تثبيت: التوقيع يُتحقَّق منه بمفتاح لا يملكه إلا صاحب
  // التثبيت. لا سرّ مشترك في التطبيق إطلاقاً، وسرّ التوقيع القديم لم يبقَ
  // له أثر — إبقاؤه كان يعني بقاء ما استُخرج من الحزمة صالحاً للأبد.
  const installId = request.headers.get('x-install-id')?.trim() ?? ''
  const sig = request.headers.get('x-app-sig')?.trim() ?? ''
  const ts = Number(request.headers.get('x-app-ts')?.trim() || '0')
  const nonce = request.headers.get('x-app-nonce')?.trim() ?? ''

  if (!installId || !sig || !ts) {
    await noteAbuse(env, request, 'missing_signature')
    await logSecurity(env, request, 'missing_signature')
    throw new HttpError(403, 'طلب غير موقّع')
  }
  // نافذة الصلاحية دقيقتان لا عشر: التوقيع لم يبقَ السرّ الوحيد، فتقصير
  // النافذة يضيّق فرصة إعادة التشغيل بلا أن يقطع تشغيلاً طويلاً — التوقيع
  // يُبنى لكل طلب على حدة، لا مرة عند بدء المشاهدة.
  if (Math.abs(Date.now() - ts) > 2 * 60 * 1000) {
    await noteAbuse(env, request, 'stale_signature')
    throw new HttpError(403, 'انتهت صلاحية التوقيع')
  }

  const row = await env.XDB
    .prepare('SELECT public_key, revoked FROM x_install_keys WHERE install_id = ?1')
    .bind(installId).first<{ public_key: string; revoked: number }>()
  if (!row) {
    await noteAbuse(env, request, 'unknown_install')
    await logSecurity(env, request, 'unknown_install', `install=${installId}`)
    throw new HttpError(403, 'تثبيت غير مسجَّل')
  }
  if (row.revoked) {
    await logSecurity(env, request, 'revoked_install', `install=${installId}`)
    throw new HttpError(403, 'تثبيت موقوف')
  }

  const url = new URL(request.url)
  const bodyHash = await bodyHashOf(request)
  // التوقيع يشمل: التثبيت + الطابع الزمني + nonce + الطريقة + المسار + بصمة
  // الجسم. بصمة الجسم تمنع اعتراض طلب موقّع وتبديل محتواه (رفع صفّ آخر،
  // تفعيل مفتاح مختلف) — وهو ما كان ممكناً حين كان التوقيع على المسار وحده.
  const payload = [
    installId, ts, nonce, request.method, url.pathname + url.search, bodyHash,
  ].join('|')

  let ok = false
  try {
    const pub = await crypto.subtle.importKey('raw', hexToBytes(row.public_key),
      { name: 'Ed25519' }, false, ['verify'])
    ok = await crypto.subtle.verify({ name: 'Ed25519' }, pub,
      hexToBytes(sig), new TextEncoder().encode(payload))
  } catch {
    ok = false
  }
  if (!ok) {
    await noteAbuse(env, request, 'bad_signature')
    await logSecurity(env, request, 'bad_signature', `install=${installId}`)
    throw new HttpError(403, 'توقيع غير صالح')
  }

  // الهوية الموثّقة تُثبَّت هنا وحدها: بعد أن أثبت التوقيع أن هذا الطلب
  // صادر عن صاحب المفتاح الخاص لهذا التثبيت. كل ما بعد هذا السطر يقرأ
  // منها ولا يقرأ ترويسة.
  verifiedInstall.set(request, installId)

  // يُسجَّل آخر طابع زمني مقبول، ويُستهلك الـnonce للطلبات الحسّاسة وحدها.
  await env.XDB.prepare(
    'UPDATE x_install_keys SET last_ts = ?1, last_seen = ?2 WHERE install_id = ?3'
  ).bind(ts, new Date().toISOString(), installId).run()

  if (nonce && isSensitive(request.method, url.pathname)) {
    // الإدراج نفسه هو الفحص: المفتاح الأساسي (install_id, nonce) يجعل
    // الطلب الثاني يفشل بلا سباق بين قراءة وكتابة.
    const claimed = await env.XDB.prepare(
      `INSERT INTO x_req_nonces (install_id, nonce, at) VALUES (?1, ?2, ?3)
       ON CONFLICT(install_id, nonce) DO NOTHING RETURNING nonce`
    ).bind(installId, nonce, Date.now()).first<{ nonce: string }>()
    if (!claimed) {
      await noteAbuse(env, request, 'nonce_reuse')
      await logSecurity(env, request, 'nonce_reuse', `install=${installId}`)
      throw new HttpError(409, 'طلب مكرّر')
    }
    // التنظيف عشوائي لا في كل طلب: صفوف أقدم من نافذة الصلاحية لم تعد
    // تحرس شيئاً — الطابع الزمني يرفضها أصلاً — فإبقاؤها ينفخ الجدول بلا
    // مقابل. الاحتمال 1/50 يجعل الكلفة مهملة ويضمن التنظيف عملياً.
    if (Math.random() < 0.02) {
      await env.XDB.prepare('DELETE FROM x_req_nonces WHERE at < ?1')
        .bind(Date.now() - 5 * 60 * 1000).run().catch(() => undefined)
    }
  }
}

/**
 * بصمة جسم الطلب — تُحسب قبل قراءة المعالج للجسم.
 *
 * `request.clone()` إلزامي: قراءة الجسم تستهلك الدفق، فتمريره للمعالج بعد
 * استهلاكه كان يجعل كل طلب POST بجسم يفشل. النسخة تُقرأ هنا والأصل يمرّ.
 *
 * الحدّ الأقصى مقصود: رفع فيديو يمرّ بجسم بمئات الميغابايت، وحساب بصمته
 * يعني سحبه كاملاً إلى الذاكرة — وهذا يهدم البثّ المدفوع بالذاكرة ويتجاوز
 * حدود العامل. فوق الحدّ تُترك البصمة فارغة، ويبقى التوقيع على المسار
 * والطابع الزمني وnonce، وتبقى تلك المسارات محكومة بجلسة المالك وبطول
 * الأجزاء. أمن الرفع لا يقوم على بصمة الجسم بل على هوية المالك وجلسته.
 */
const MAX_BODY_HASH = 256 * 1024

async function bodyHashOf(request: Request): Promise<string> {
  if (request.method === 'GET' || request.method === 'HEAD') return ''
  const declared = Number(request.headers.get('content-length') ?? '0')
  if (!declared || declared > MAX_BODY_HASH) return ''
  try {
    const buf = await request.clone().arrayBuffer()
    if (buf.byteLength > MAX_BODY_HASH) return ''
    const digest = await crypto.subtle.digest('SHA-256', buf)
    return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('')
  } catch {
    return ''
  }
}

/**
 * الطلبات التي تستهلك nonce: ما يغيّر حالة أو يصرف رصيداً.
 *
 * القراءات لا تستهلكه: كتابة صفّ لكل قراءة كانت سترفع كلفة D1 بلا مقابل
 * أمني — إعادة قراءة لا تضرّ، وإعادة صرفٍ تضرّ.
 */
function isSensitive(method: string, pathname: string): boolean {
  if (method === 'GET' || method === 'HEAD') return false
  return true
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim()
  const out = new Uint8Array(clean.length >> 1)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16)
  }
  return out
}

/**
 * كشف مزرعة الأجهزة: عدة أجهزة تتشارك عنواناً واحداً.
 *
 * العتبة كانت 30 جهازاً في اليوم، وهي منخفضة جداً لأن مشغّلي الجوال
 * يستخدمون CGNAT: عشرات المستخدمين الحقيقيين يظهرون بالعنوان نفسه خلال
 * ساعات، فيُحظر العنوان كله ويمنع من لم يذنب. صار الكشف يسجّل للمالك أولاً،
 * ولا يحظر إلا بعد تكرار التجاوز في نوافذ متعددة — أي سلوك ثابت لا صدفة
 * ازدحام عابرة.
 */
async function trackDeviceFarm(env: Env, request: Request): Promise<void> {
  const dev = deviceOf(request)
  const addr = ip(request)
  if (!dev || addr === 'unknown') return
  if (await kvGet(env, `devban:${dev}`)) return
  const key = `devs:${addr}`
  const list = ((await env.QUOTA.get(key, 'json')) as string[] | null) ?? []
  if (list.includes(dev)) return
  list.push(dev)
  if (list.length > 400) {
    const strikes = Number(await env.QUOTA.get(`farmstrikes:${addr}`)) || 0
    await env.QUOTA.put(`farmstrikes:${addr}`, String(strikes + 1), { expirationTtl: 7 * DAY })
    await logSecurity(env, request, 'device_farm', `devices=${list.length} strikes=${strikes + 1}`)
    if (strikes + 1 >= 3) {
      await env.QUOTA.put(`hardban:${addr}`, 'device-farm', { expirationTtl: DAY })
      await logSecurity(env, request, 'ip_hardban', `device-farm strikes=${strikes + 1}`)
    }
  }
  await env.QUOTA.put(key, JSON.stringify(list.slice(-500)), { expirationTtl: DAY })
}

/** ربط الحساب بجهاز واحد — أي جهاز آخر يُرفض ويُسجَّل */
async function assertDeviceBound(env: Env, request: Request, user: XUser): Promise<void> {
  const dev = deviceOf(request)
  if (!dev) return
  if (user.role === 'owner') return
  if (!user.device_id) {
    await env.XDB.prepare('UPDATE x_users SET device_id = ?1 WHERE id = ?2').bind(dev, user.id).run()
    return
  }
  if (user.device_id !== dev) {
    await logSecurity(env, request, 'device_mismatch', `bound=${user.device_id} got=${dev} user=${user.username}`)
    throw new HttpError(403, 'هذا الحساب مرتبط بجهاز آخر — تواصل مع المالك')
  }
}

async function authenticate(env: Env, request: Request): Promise<{ caller: Caller; user: XUser | null }> {
  const token = request.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim()
  if (!token) throw new HttpError(401, 'missing token')

  // جلسة المالك تُجرَّب أولاً بسرّها المستقل. رمز بتوقيع صحيح لكن بلا
  // typ=owner لا يُقبل هنا، فلا يمكن تحويل جلسة عادية إلى جلسة مالك.
  const asOwner = await tryOwnerToken(env, token)
  if (asOwner) {
    const owner = await xUser(env.XDB, String(asOwner.sub))
    if (!owner || owner.role !== 'owner' || !owner.active) {
      throw new HttpError(401, 'invalid token')
    }
    return { caller: { uid: owner.id, role: 'owner' }, user: owner }
  }

  const payload = await verifyJwt(token, env.X_JWT_SECRET)
  const sub = typeof payload.sub === 'string' ? payload.sub : ''
  if (!sub) throw new HttpError(401, 'invalid token')
  const role = typeof payload.role === 'string' ? payload.role : 'guest'

  if (role === 'guest') {
    // الزائر: جلسة مرتبطة بالتثبيت الموثّق — بلا صف في x_users.
    // كان الربط بـ`payload.dev` من ترويسة يملك العميل تغييرها، فمن سرق رمز
    // زائر استعمله من أي مكان. المفتاح الخاص لا ينتقل، فالتثبيت هو الحدّ.
    const inst = verifiedInstallOf(request)
    if (payload.inst && inst && payload.inst !== inst) {
      await logSecurity(env, request, 'guest_token_install_mismatch')
      throw new HttpError(401, 'invalid token')
    }
    return { caller: { uid: sub, role }, user: null }
  }

  const user = await xUser(env.XDB, sub)
  if (!user) throw new HttpError(401, 'invalid token')
  if (!user.active) throw new HttpError(403, 'الحساب بانتظار تفعيل المالك')
  if (user.expires_at > 0 && Date.now() >= user.expires_at) {
    throw new HttpError(403, 'انتهى اشتراكك — تواصل مع المالك')
  }
  await assertDeviceBound(env, request, user)
  return { caller: { uid: user.id, role: user.role }, user }
}

/** بوابة الإصدارات — تُعيد استجابة 426 غنية (رسالة+صورة+زر) أو null إن مسموح */
function versionGate(request: Request, settings: XSettings): Response | null {
  const v = versionOf(request)
  // ترويسة غائبة أو غير مقروءة تعني عميلاً لا يعرف البوابة أصلاً. كان
  // يُقبل لأن `v <= 0`، وهذا بالضبط سبب عمل الإصدار 1 رغم رفع الحدّ الأدنى
  // إلى 2: حذف الترويسة كان يتجاوز البوابة كلها. ما دام المالك قد فعّل
  // حدّاً أدنى (> 1)، فغياب الترويسة حجب لا سماح.
  if (v <= 0) {
    if (settings.minVersion <= 1) return null
    return blockedResponse(settings)
  }
  if (v < settings.minVersion || settings.blockedVersions.includes(v)) {
    return blockedResponse(settings)
  }
  return null
}

/** استجابة 426 الموحّدة — نفس الشكل في مسار غياب الترويسة ومسار الإصدار الأقدم */
function blockedResponse(settings: XSettings): Response {
  return json({
    ok: false,
    error: 'إصدار التطبيق غير مدعوم — حدّث التطبيق',
    status: 426,
    update: {
      required: true,
      message: settings.updateMessage,
      url: settings.updateUrl,
      imageUrl: settings.updateImageUrl
    }
  }, 426)
}

/**
 * بصمة الجهاز كما يرسلها العميل — تُستعمل للعرض فقط، لا للسلطة.
 *
 * معرّف الجهاز كان يُولَّد داخل التطبيق ويُخزَّن مع بياناته، فمسح البيانات
 * يمحوه ويعود المستخدم بمنحة جديدة. البصمة تأتي من النظام (ANDROID_ID)
 * وتُخزَّن في التخزين الأصلي، فتبقى بعد مسح البيانات وبعد تبديل الحساب.
 *
 * تحذير كان مكتوباً هنا خطأً: «التوقيع يشملها فتبديلها يكسر التوقيع» غير
 * صحيح. نصّ التوقيع هو `installId|ts|nonce|method|path|bodyHash`، والبصمة
 * ليست فيه. لذلك لا تُشتقّ منها سلطة هنا: تُمرَّر إلى `walletKey` التي تربطها
 * بالتثبيت الموثّق مرة واحدة، ثم تتجاهلها.
 */
function fingerprint(request: Request): string {
  const fp = request.headers.get('x-device-fp')?.trim() ?? ''
  if (/^[0-9a-f]{16,64}$/i.test(fp)) return `fp:${fp.toLowerCase()}`
  // نسخ قديمة لا ترسل بصمة: معرّف الجهاز أفضل من لا شيء، ثم العنوان كحل أخير.
  const dev = deviceOf(request)
  return dev ? `dev:${dev}` : `ip:${ip(request)}`
}

/**
 * مفتاح محفظة الزائر: يُثبَّت على التثبيت الموثّق عند أول ظهور، ثم لا يُقرأ
 * من الترويسة بعدها أبداً.
 *
 * العلة التي أُغلقت: كان المفتاح هو `x-device-fp` المُرسَل من العميل. ومعرّف
 * الجهاز ليس سراً — يظهر في الدردشة وفي تصدير اللوحة — فمن قرأه أرسله مع
 * بصمته وصرف رصيد الضحية بلا جلسته ولا بصمته. والبصمة الواحدة كانت تكفي
 * لفتح كل ملف ودخول كل شركة من رصيد غيره.
 *
 * الحلّ: الربط يُخزَّن على الخادم مرة واحدة (`x_wallet_bindings`)، وبعدها
 * مفتاح المحفظة يأتي من المخزَّن لا من الطلب. تغيير الترويسة بعد الربط
 * لا يُنتج هوية جديدة ولا يصل إلى محفظة أحد.
 *
 * والمحفظة القائمة تبقى قابلة للوصول: من كان مفتاحه `fp:X` يُربط به عند
 * أول طلب ويحتفظ برصيده. لكن بصمة مملوكة لتثبيت آخر لا تُتبنّى — صاحبها
 * لا يفقدها لمن أرسلها.
 */
async function walletKey(env: Env, request: Request, fp: string): Promise<string> {
  const installId = verifiedInstallOf(request)
  // طلب بلا تثبيت موثّق: لا سلطة تُبنى عليه. مفتاح معزول لا يُخلط بأحد.
  if (!installId) return `anon:${ip(request)}`

  const bound = await env.XDB.prepare(
    'SELECT wallet_key FROM x_wallet_bindings WHERE install_id = ?1'
  ).bind(installId).first<{ wallet_key: string }>()
  // الربط القائم هو الحكم: الترويسة لا تُقرأ إطلاقاً بعد هذه اللحظة.
  if (bound) return bound.wallet_key

  // أول ظهور: تُتبنّى البصمة إن كانت حرّة، وإلا مفتاح خاص بهذا التثبيت.
  // البصمة المملوكة لتثبيت آخر تُرفض، فلا تُسرق محفظة قائمة.
  let key = `in:${installId}`
  if (fp.startsWith('fp:')) {
    const taken = await env.XDB.prepare(
      'SELECT 1 x FROM x_wallet_bindings WHERE wallet_key = ?1'
    ).bind(fp).first()
    if (!taken) key = fp
  }
  await env.XDB.prepare(
    `INSERT INTO x_wallet_bindings (install_id, wallet_key, bound_at)
     VALUES (?1, ?2, ?3) ON CONFLICT(install_id) DO NOTHING`
  ).bind(installId, key, new Date().toISOString()).run().catch(() => undefined)

  // إعادة القراءة: طلبان أولان متزامنان قد يسبق أحدهما الآخر، والمخزَّن هو
  // الحكم حتى لا يرى المستخدم محفظتين في طلبين متتاليين.
  const again = await env.XDB.prepare(
    'SELECT wallet_key FROM x_wallet_bindings WHERE install_id = ?1'
  ).bind(installId).first<{ wallet_key: string }>()
  return again?.wallet_key ?? key
}

/** مفتاح الهوية لهذا الطلب — يُحسب مرة ويُمرَّر لكل عمليات الخصم والعرض. */
async function walletOf(env: Env, request: Request): Promise<string> {
  return walletKey(env, request, fingerprint(request))
}

/**
 * هل بدّل المستخدم بصمة جهازه ليعيد الحصول على منحة جديدة؟
 *
 * البصمة تُقارن بعضوية موثوقة: لغير المسجّل معرّف الجهاز الموقّع في جلسته
 * (يُتحقق منه في `authenticate`)، وللمسجّل معرّف حسابه. البصمة تُثبَّت على
 * العضوية أول مرة تُرى، فتبديلها بعد ذلك لا يُنتج هوية جديدة.
 *
 * هذا هو الفرق بين إصلاح العلة وترقيعها: كان الخصم بمفتاح `fp` المُرسَل من
 * العميل، وتبديله يمنح منحة يومية جديدة كل مرة، وعملات هديّة جديدة، وكل
 * المخططات مجاناً بلا حد. ربط البصمة بالعضوية يجعل الهوية واحدة ولو بدّل
 * الجهاز بصمته ألف مرة.
 *
 * لا نحظر صاحب البصمة المبدَّلة ولا نمنع صرفه عملاته المشتراة — نمنعه من
 * المنحة المجانية والهديّة وحدهما، وهو ما كان يُستغَل. من غيّر بصمته
 * لحادث جهاز حقيقي يتواصل مع المالك، والناس العاديون لا يبدّلونها أصلاً.
 */
async function fingerprintRotated(
  env: Env, request: Request, caller: Caller
): Promise<boolean> {
  const fp = request.headers.get('x-device-fp')?.trim().toLowerCase() ?? ''
  // نسخ قديمة لا ترسل بصمة — لا شيء نربطه ولا شيء نمنعه.
  if (!/^[0-9a-f]{16,64}$/.test(fp)) return false
  // العضوية للتثبيت الموثّق: كان `d:${deviceOf(request)}` وهو ما يملك
  // العميل تغييره، فيكفي تبديل ترويسة لتبدو البصمة جديدة وتُعاد المنحة.
  const installId = verifiedInstallOf(request)
  const who = caller.role === 'user' || caller.role === 'owner'
    ? `u:${caller.uid}`
    : `d:${installId}`
  if (!installId && !who.startsWith('u:')) return false
  const key = `fpb:${who}`
  const bound = await kvGet(env, key)
  if (!bound) {
    try {
      await env.QUOTA.put(key, fp, { expirationTtl: 90 * DAY })
    } catch { /* تعذّر التثبيت لا يمنع الطلب */ }
    return false
  }
  if (bound === fp) return false
  await logSecurity(env, request, 'fingerprint_rotated', `who=${who}`)
  return true
}

/**
 * خصم من عملات الهوية: حساب المسجّل من x_users، ومحفظة الزائر من جدولها.
 * يُعيد الرصيد بعد الخصم، أو null إذا لم يكفِ الرصيد.
 */
async function spendCoins(
  env: Env, caller: Caller, fp: string, cost: number
): Promise<number | null> {
  const now = Date.now()
  if (caller.role === 'user') {
    const row = await env.XDB.prepare(
      `UPDATE x_users SET quota_balance = quota_balance - ?3
       WHERE id = ?1 AND quota_balance >= ?3
         AND (quota_expires_at = 0 OR quota_expires_at > ?2)
       RETURNING quota_balance`
    ).bind(caller.uid, now, cost).first<{ quota_balance: number }>()
    return row ? row.quota_balance : null
  }
  const w = await env.XDB.prepare(
    `UPDATE x_guest_wallets SET balance = balance - ?3
     WHERE device_id = ?1 AND balance >= ?3
       AND (expires_at = 0 OR expires_at > ?2)
     RETURNING balance`
  ).bind(fp, now, cost).first<{ balance: number }>()
  return w ? w.balance : null
}

/** سبب نفاد الرصيد: رسالة دقيقة تفرّق بين انتهاء الصلاحية ونفاده. */
async function emptyReason(env: Env, caller: Caller, fp: string): Promise<HttpError> {
  const now = Date.now()
  if (caller.role === 'user') {
    const u = await xUser(env.XDB, caller.uid)
    if (u && u.quota_expires_at > 0 && u.quota_expires_at <= now) {
      return new HttpError(402, 'انتهت صلاحية عملاتك — جدّد باقتك عبر التواصل مع المالك')
    }
    return new HttpError(402, 'انتهت حصتك المجانية ولا توجد عملات — اشترِ باقة من المالك')
  }
  const wallet = await env.XDB.prepare(
    'SELECT balance, expires_at FROM x_guest_wallets WHERE device_id = ?1'
  ).bind(fp).first<{ balance: number; expires_at: number }>()
  if (wallet && wallet.expires_at > 0 && wallet.expires_at <= now) {
    return new HttpError(402, 'انتهت صلاحية عملاتك — تواصل مع المالك للتجديد')
  }
  return new HttpError(402,
    'انتهت حصتك المجانية ولا توجد عملات — تواصل مع المالك لإنشاء حساب أو شحن رصيد')
}

/**
 * خصم موحّد: المنحة اليومية أولاً ثم العملات.
 *
 * الترتيب واحد لفتح المخططات ودخول شركة في التوافقات: العدّاد واحد والعملات
 * واحدة، فلا يفاجأ المستخدم بأن رصيده في الشريط لا يطابق ما يُخصم فعلاً.
 */
async function chargeOne(
  env: Env, caller: Caller, fp: string, settings: XSettings,
  addr = '', rotated = false, price: number | null = null
): Promise<{ freeLeft: number; balance: number; source: string }> {
  if (caller.role === 'owner') return { freeLeft: -1, balance: -1, source: 'owner' }

  // بصمة مبدَّلة: لا منحة مجانية. لا يُرفض الطلب كله — من دفع عملاته يجب
  // أن يصرفها، والعقوبة على المُستغَل وحده (المنحة) لا على الرصيد المدفوع.
  if (!rotated) {
    // المنحة الشخصية أولاً، ثم سقف العنوان: لو سبق سقف العنوان لكانت
    // الهوية الواحدة تُخصم منها منحة لم تُمنح أصلاً. فحص العنوان يقع بعد
    // نجاح المنحة الشخصية فقط، فلا يُخصم من سقف العنوان طلب لم يُمنح.
    const automaticFreeQuota = 0
    const freeLeft = await takeDailyFree(env.XDB, fp, automaticFreeQuota)
    if (freeLeft >= 0) {
      if (await takeDailyFreeByIp(env.XDB, addr, settings.dailyFreeQuota)) {
        return { freeLeft, balance: -1, source: 'free' }
      }
      // بلغ العنوان سقفه: تبقى المنحة مستهلكة لهذه الهوية كي لا يستمر
      // التفريخ، وينتقل الطلب للعملات إن وُجدت.
    }
  }

  // إن مُرِّر سعر صريح فهو المعتمد، ولو كان صفراً: المالك قد يجعل المخططات
  // مجانية (بالمنحة فقط) بينما التوافقات مدفوعة. غياب السعر (null) يعني
  // مساراً لم يُحدَّد له ثمن فيرجع لسعر التوافقات كي لا يصير مجانياً بالخطأ.
  const cost = price === null
    ? Math.max(1, Math.floor(Number(settings.compatSearchCost) || 1))
    : Math.max(0, Math.floor(price) || 0)
  if (cost <= 0) return { freeLeft: 0, balance: -1, source: 'free' }
  const balance = await spendCoins(env, caller, fp, cost)
  if (balance === null) throw await emptyReason(env, caller, fp)
  return { freeLeft: 0, balance, source: 'coins' }
}

/**
 * فتح ملف مخطط مع إعفاء إعادة الفتح.
 *
 * يُخصم مرة واحدة لكل (جهاز + ملف + يوم). إعادة فتح نفس المخطط — وهو سلوك
 * طبيعي جداً في الاستعمال — كانت تُخصم في كل مرة وتستنزف المنحة على ملف
 * واحد. المفاتيح في KV بصلاحية يومين كي لا تتراكم.
 */
async function consumeFileOnce(
  env: Env, ctx: ExecutionContext, request: Request, caller: Caller,
  settings: XSettings, fp: string, fileKey: string
): Promise<number> {
  const digest = await hmacHex(settings.telegramLink || 'x-file', `${fp}|${fileKey}|${today()}`)
  const seenKey = `fo:${fp}:${digest.slice(0, 32)}`
  const cached = await kvGet(env, seenKey)
  if (cached) return Number(cached)

  const r = await chargeOne(env, caller, fp, settings, ip(request),
    await fingerprintRotated(env, request, caller), settings.schemFilePrice)
  const left = r.source === 'free' ? r.freeLeft : r.balance
  ctx.waitUntil(env.QUOTA.put(seenKey, String(left), { expirationTtl: 2 * DAY })
    .catch(() => {}))
  return left
}

// ============================== Mirror reads (READ-ONLY) ==============================

interface MirrorDoc { id: string; fields: Record<string, any> }

function mrows(result: D1Result<{ id: string; data: string }>): MirrorDoc[] {
  return (result.results ?? []).map(r => ({ id: r.id, fields: JSON.parse(r.data) }))
}

async function mirrorCollection(db: D1Database, collection: string): Promise<MirrorDoc[]> {
  return mrows(await db.prepare(
    'SELECT id, data FROM docs WHERE collection = ?1 ORDER BY sort_order IS NULL, sort_order, id'
  ).bind(collection).all<{ id: string; data: string }>())
}

async function mirrorSearchCompat(
  db: D1Database, opts: { query: string; brandFile?: string; type?: string; keyword?: string; limit: number }
): Promise<MirrorDoc[]> {
  const clauses = ["collection = 'compatibility'"]
  const binds: (string | number)[] = []
  if (opts.brandFile) { binds.push(opts.brandFile); clauses.push(`brand_file = ?${binds.length}`) }
  if (opts.type) { binds.push(opts.type); clauses.push(`component_type = ?${binds.length}`) }
  if (opts.keyword) { binds.push(`%${opts.keyword.toLowerCase()}%`); clauses.push(`LOWER(data) LIKE ?${binds.length}`) }
  // كل كلمة شرط مستقل (AND): بحث «iphone 11» كان يرجع صفراً لأن المطابقة
  // كانت على النص كاملاً. سقف 4 كلمات يحدّ كلفة الاستعلام.
  // ترتيب الكلمات لا يجوز أن يحجب النتيجة: «سمارت 7» و«7 سمارت» يبحثان عن
  // الشيء نفسه، وكلاهما يُفرض عليه AND بترتيب مختلف — وهو ترتيب لا معنى له
  // في قاعدة تحفظ النص مسلسلاً. لذلك تُرتَّب الكلمات في الاستعلام نفسه.
  const tokens = opts.query.toLowerCase().split(/\s+/).filter(Boolean).slice(0, 4).sort()
  for (const t of tokens) {
    binds.push(`%${t}%`)
    clauses.push(`LOWER(data) LIKE ?${binds.length}`)
  }
  // نجلب أكثر من الحدّ ثم نرتّب بالأهمية: الاستعلام بلا ORDER BY كان يُرجع
  // الصفوف بترتيب تخزين اعتباطي، فيظهر السجل المطابق تماماً بعد صفّين.
  const fetchLimit = Math.min(opts.limit * 3, 360)
  binds.push(fetchLimit)
  const rows = mrows(await db.prepare(
    `SELECT id, data FROM docs WHERE ${clauses.join(' AND ')}
     ORDER BY sort_order IS NULL, sort_order, id LIMIT ?${binds.length}`
  ).bind(...binds).all<{ id: string; data: string }>())

  // الترتيب النهائي في JS: أسماء الحقول في `data` JSON غير موثّقة في القاعدة،
  // فالاعتماد على json_extract لأسماء مخمّنة هشّ. هنا نقرأ الحقول المحلّلة.
  const q = opts.query.toLowerCase().trim()
  const scored = rows.map(d => ({ d, s: relevanceScore(d.fields, tokens, q) }))
  scored.sort((a, b) => b.s - a.s || a.d.id.localeCompare(b.d.id))
  return scored.slice(0, opts.limit).map(x => x.d)
}

/**
 * تعديلات المالك على التوافقات — طبقة تُدمج فوق سجلات المرآة عند القراءة.
 *
 * المرآة مصدر قراءة فقط ولا تُكتب أبداً؛ كل تحرير يقع في `x_compat_edits`.
 * لذلك أي مسار يقرأ توافقات للمستخدمين يجب أن يمرّ من هنا، وإلا ظلّ
 * التحرير محبوساً في اللوحة ويرى المستخدم البيانات الأصلية وحدها.
 */
async function compatEditsFor(env: Env, brandFile?: string): Promise<Map<string, any>> {
  // `kind` لازم للدمج: بدون معرفة أن الصفّ `patch` على المرآة أو `new` من
  // المالك، لا يمكن جلب صفوف المرآة التي غيّرها المالك حين لا يعيدها البحث.
  const rows = brandFile
    ? await env.XDB.prepare(
        'SELECT doc_key, data, kind, deleted FROM x_compat_edits WHERE brand_file = ?1'
      ).bind(brandFile).all<any>()
    : await env.XDB.prepare(
        'SELECT doc_key, data, kind, deleted FROM x_compat_edits'
      ).all<any>()
  const m = new Map<string, any>()
  for (const r of rows.results ?? []) m.set(r.doc_key, r)
  return m
}

/** هل يطابق صفٌّ (بعد التحليل) بحث المستخدم؟ نفس شرط المرآة: كل الكلمات. */
function compatRowMatches(
  fields: Record<string, any>, tokens: string[], keyword: string | undefined,
  type: string | undefined
): boolean {
  if (type && String(fields.componentType ?? '').toUpperCase() !== type) return false
  const hay = JSON.stringify(fields).toLowerCase()
  if (keyword && !hay.includes(keyword.toLowerCase())) return false
  return tokens.every(t => hay.includes(t))
}

/**
 * يدمج تعديلات المالك في نتائج بحث المرآة ويضمّ الصفوف التي أنشأها.
 *
 * الصفوف الجديدة لا وجود لها في المرآة، فلا يجدها بحث المستخدم أبداً بلا
 * ضمّها هنا — وهي الغرض كله من الإضافة. تظهر للجميع لا للمالك وحده.
 */
async function mergeCompatEdits(
  env: Env,
  brandFile: string | undefined,
  results: MirrorDoc[],
  tokens: string[],
  keyword: string | undefined,
  type: string | undefined,
  limit: number
): Promise<MirrorDoc[]> {
  const edits = await compatEditsFor(env, brandFile)
  const out: MirrorDoc[] = []
  const seen = new Set<string>()
  for (const d of results) {
    const e = edits.get(d.id)
    if (e?.deleted) continue
    let fields = d.fields
    if (e) {
      try {
        fields = { ...fields, ...JSON.parse(e.data) }
      } catch { /* تعديل تالف لا يُسقط الصفّ */ }
    }
    if (!compatRowMatches(fields, tokens, keyword, type)) continue
    out.push({ id: d.id, fields })
    seen.add(d.id)
  }
  if (!brandFile) return out.slice(0, limit)

  // صفّ المرآة لا يعود من البحث إلا إذا طابق نصّه **الأصلي**؛ فلو أضاف المالك
  // موديلاً جديداً وبحث عنه، لم يجده المرآة أصلاً ولم يصل الدمج. نجلب صفوف
  // المرآة المُعدَّلة بالمعرّف ونطابقها على النسخة النهائية بعد الدمج، فيرى
  // المالك ما كتبه في البحث نفسه الذي يراه به المستخدمون.
  const patchedIds: string[] = []
  for (const [docKey, e] of edits) {
    if (e?.deleted || seen.has(docKey)) continue
    if (!e?.kind || e.kind !== 'patch') continue
    patchedIds.push(docKey)
  }
  if (patchedIds.length) {
    // على دفعات: قائمة `IN` بآلاف المعرّفات تتجاوز حدّ معاملات الاستعلام
    // الواحد في D1، فيسقط البحث كله بسبب عدد التعديلات لا بسبب البحث نفسه.
    const chunk = 80
    for (let i = 0; i < patchedIds.length; i += chunk) {
      const part = patchedIds.slice(i, i + chunk)
      const placeholders = part.map((_, n) => `?${n + 1}`).join(',')
      const src = await env.MIRROR.prepare(
        `SELECT id, data FROM docs
         WHERE collection = 'compatibility' AND id IN (${placeholders})`
      ).bind(...part).all<{ id: string; data: string }>()
      for (const d of mrows(src)) {
        if (seen.has(d.id)) continue
        const e = edits.get(d.id)
        if (e?.deleted) continue
        let fields = d.fields
        try {
          fields = { ...fields, ...JSON.parse(e.data) }
        } catch { continue }
        if (!compatRowMatches(fields, tokens, keyword, type)) continue
        out.push({ id: d.id, fields })
        seen.add(d.id)
      }
    }
  }

  const newRows = await env.XDB.prepare(
    `SELECT doc_key, data FROM x_compat_edits
     WHERE brand_file = ?1 AND kind = 'new' AND deleted = 0`
  ).bind(brandFile).all<any>()
  for (const r of newRows.results ?? []) {
    if (seen.has(r.doc_key)) continue
    let f: Record<string, any>
    try {
      f = JSON.parse(r.data)
    } catch { continue }
    if (!compatRowMatches(f, tokens, keyword, type)) continue
    out.push({ id: r.doc_key, fields: f })
  }

  // الترتيب: نتائج المرآة أولاً كما رتّبها المرآة، ثم الصفوف المضافة إليها
  // من التعديلات. لا نعيد الترتيب هنا حتى لا ننافس ترتيب البحث الأصلي.
  return out.slice(0, limit)
}

/** أنواع القطع التي أضافها المالك لشركة — كانت تُعرض في اللوحة وحدها. */
async function compatOwnerTypes(env: Env, brandFile: string): Promise<string[]> {
  const rows = await env.XDB.prepare(
    `SELECT data FROM x_compat_edits WHERE brand_file = ?1 AND kind = 'cat' AND deleted = 0`
  ).bind(brandFile).all<any>()
  const out: string[] = []
  for (const r of rows.results ?? []) {
    try {
      const t = String(JSON.parse(r.data)?.name ?? '').toUpperCase()
      if (t && !out.includes(t)) out.push(t)
    } catch { /* تجاهل */ }
  }
  return out
}

/**
 * تطبيع النص قبل المقارنة: حذف الفواصل والأشكال المتشابهة وعلامات التشكيل.
 *
 * مشترك بين الترتيب والبحث لأن كليهما يقارن نصّ المستخدم بنصّ البيانات،
 * والاثنان يكتبان الشيء نفسه بصيغتين («smart7» و«smart 7»).
 */
const squash = (v: string) =>
  v.replace(/[\s\u0640\-_\/\\.,+()]+/g, "").replace(/[\u064B-\u0652\u0670]/g, "")

/**
 * درجة ملاءمة سجل لعبارة البحث — الأعلى أولاً.
 *
 * بنية سجل التوافقات: `compatibleModels` قائمة موديلات، و`subCategory` كائن
 * فيه `name`، و`componentType` نوع القطعة. المطابقة في موديل بعينه أقوى دليل
 * من مطابقة عابرة في نص الحقل كله. بلا هذا الترتيب يظهر سجل هامشي قبل السجل
 * الذي يبحث عنه المستخدم حرفياً.
 */
function relevanceScore(fields: Record<string, unknown>, tokens: string[], q: string): number {
  const models = Array.isArray(fields.compatibleModels)
    ? (fields.compatibleModels as unknown[]).map(m => String(m).toLowerCase())
    : [];
  const sub = (fields.subCategory && typeof fields.subCategory === 'object')
    ? String((fields.subCategory as Record<string, unknown>).name ?? '').toLowerCase()
    : String(fields.subCategory ?? '').toLowerCase();
  const hay = JSON.stringify(fields).toLowerCase()

  // الترتيب يُبنى على أفضل موديل في السجل لا على مجموع كل الموديلات:
  // سجل فيه عشرة موديلات كلها مطابقة جزئية كان يسبق سجلاً فيه الموديل
  // المطلوب حرفياً. المهم أن يوجد موديل واحد مطابق تماماً.
  // المطابقة تُجرَّب على الصيغة المُطبَّعة لا الخام وحدها: المستخدم يكتب
  // «smart7» بينما البيانات تحفظ «smart 7»، وبلا حذف الفاصل يخرج البحث
  // فارغاً وهو يرى السطر أمامه.
  const cq2 = squash(q)
  const cTokens = tokens.map(t => squash(t)).filter(Boolean)
  const cSub = squash(sub)
  const cHay = squash(hay)

  let best = 0
  for (const m of models) {
    const cm = squash(m)
    let s = 0
    if (cq2 && cm === cq2) s = 100
    else if (cq2 && cm.startsWith(cq2)) s = 80
    // اسم الموديل يُكتب في البيانات مسبوقاً بالشركة («xiaomi redmi note 11»)،
    // فمطابقة الذيل تطابق الاسم الذي كتبه المستخدم.
    else if (cq2 && cm.endsWith(cq2)) s = 70
    else if (cq2 && cq2.length >= 3 && cm.includes(cq2)) s = 60
    else s = cTokens.reduce((acc, t) =>
      acc + (cm === t ? 50 : cm.startsWith(t) ? 30 : cm.includes(t) ? 18 : 0), 0)
    if (s > best) best = s
  }

  // كسر التعادل: مطابقة النوع الفرعي، ثم أي مطابقة في السجل كله.
  let tie = cTokens.reduce((acc, t) => acc + (cSub.includes(t) ? 4 : 0), 0)
  for (const t of cTokens) if (cHay.includes(t)) tie += 1
  return best * 1000 + tie
}

/** الأنواع المتوفرة لشركة — استعلام تجميعي واحد، مخزّن مؤقتاً. */
async function compatTypesOf(db: D1Database, brandFile: string): Promise<string[]> {
  const rows = await db.prepare(
    `SELECT component_type t, COUNT(*) c FROM docs
     WHERE collection = 'compatibility' AND brand_file = ?1
     GROUP BY component_type ORDER BY c DESC`
  ).bind(brandFile).all<{ t: string; c: number }>()
  return (rows.results ?? []).map(r => r.t).filter(Boolean)
}

/** كل ملفات الشركات المتوفرة في المرآة — لتصفية سجل التثبيتات حسب النشاط. */
async function compatBrandFiles(db: D1Database): Promise<string[]> {
  const rows = await db.prepare(
    "SELECT DISTINCT brand_file f FROM docs WHERE collection = 'compatibility'"
  ).all<{ f: string }>()
  return (rows.results ?? []).map(r => r.f).filter(Boolean)
}

// ---------- تحصيل التوافقات ----------

// الثمن والمنحة صارا في chargeOne: عدّاد واحد وعملة واحدة للمخططات والتوافقات.

/**
 * حصة مجانية ذرّية في D1.
 *
 * عدّاد KV لا يصلح للحصص: القراءة ثم الكتابة عمليتان منفصلتان، فطلبان
 * متقاربان يقرآن نفس القيمة فيُمنحان بحثاً زائداً. هنا الزيادة والشرط داخل
 * UPDATE واحد، فلا سباق ولا تجاوز حتى مع الطلبات المتزامنة.
 *
 * يُعيد ما تبقّى، أو -1 إذا نفدت الحصة (أو كانت صفراً).
 */
async function takeDailyFree(
  db: D1Database, fp: string, limit: number
): Promise<number> {
  if (!(limit > 0)) return -1
  const row = await db.prepare(
    `INSERT INTO x_quota_daily (uid, day, kind, used) VALUES (?1, ?2, 'all', 1)
     ON CONFLICT(uid, day, kind) DO UPDATE SET used = used + 1 WHERE used < ?3
     RETURNING used`
  ).bind(fp, today(), limit).first<{ used: number }>()
  // لا صف يعني أن الشرط لم يتحقق: الحصة مستنفدة فعلاً.
  return row ? Math.max(0, limit - row.used) : -1
}

/**
 * سقف المنحة اليومية على العنوان، لا على الهوية وحدها.
 *
 * الهوية (`fp`) يرسلها العميل ويمكن تبديلها بحرية، فمن يدوّرها يأخذ منحة
 * جديدة كل مرة — كل المخططات مجاناً بلا حد. المنحة مربوطة بالمحفظة لا
 * بالجهاز، فلا يكفي أن نعرف أن أجهزة هذا العنوان كثيرة؛ نمنع التفريخ من
 * أصله: عنوان واحد لا يحصل على أكثر من ضعف ما تحصل عليه هوية واحدة، أي
 * أن تبديل الهويات لم يعد يجدي لأن العنوان هو الحدّ الحقيقي.
 *
 * العدّاد في D1 لا KV: التحديث ذرّي، فلا سباق بين طلبات متزامنة.
 * الطبيعيون لا يتأثرون: أسرة أو مقهى خلف عنوان واحد نادراً ما يبلغون
 * هذا السقف، والعنوان المشترك الضخم (CGNAT) قد يبلغه — فيُمنح الفائض
 * عندها حصته التالية في اليوم التالي بدل أن يُحجب.
 */
async function takeDailyFreeByIp(
  db: D1Database, addr: string, limit: number
): Promise<boolean> {
  if (!addr || addr === 'unknown') return true
  const cap = Math.max(limit * 2, 20)
  const row = await db.prepare(
    `INSERT INTO x_quota_daily (uid, day, kind, used) VALUES (?1, ?2, 'ipfree', 1)
     ON CONFLICT(uid, day, kind) DO UPDATE SET used = used + 1 WHERE used < ?3
     RETURNING used`
  ).bind(`ip:${addr}`, today(), cap).first<{ used: number }>()
  return !!row
}

/** ما استُهلك اليوم من المنحة — للعرض في /v1/me. */
async function dailyFreeUsed(db: D1Database, fp: string): Promise<number> {
  const row = await db.prepare(
    "SELECT used FROM x_quota_daily WHERE uid = ?1 AND day = ?2 AND kind = 'all'"
  ).bind(fp, today()).first<{ used: number }>()
  return row?.used ?? 0
}

/**
 * فتح شركة في التوافقات — نقطة الخصم الوحيدة.
 *
 * الخصم مرتبط بـ(الجهاز + الشركة + اليوم)، لا بنص البحث: المستخدم كان
 * يُحاسَب مع كل حرف يكتبه ويُحاسَب مرة أخرى عند كل تصفية، فيُستنزف قبل أن
 * يرى نتيجة. الآن يدفع مرة واحدة عند دخول الشركة، ويتنقّل بين الأنواع
 * والنصوص والنتائج بلا خصم. الخروج من الشركة والعودة لا يُعيد الخصم في
 * اليوم نفسه، فيبقى الاستعمال الطبيعي بلا مفاجآت.
 *
 * وهو أيضاً ما يمنع سحب التوافقات آلياً: كل شركة تُكلّف مرة، فسحب الكتالوغ
 * كاملاً يتطلب دفع ثمن كل شركة — بخلاف الخصم على النص الذي كان يمكن
 * تجاوزه باستعلام واحد واسع.
 */
async function ensureCompatOpen(
  env: Env, ctx: ExecutionContext, request: Request, caller: Caller,
  settings: XSettings, fp: string, brandRef: string
): Promise<{ freeLeft: number; balance: number; charged: boolean; source: string }> {
  if (caller.role === 'owner') {
    return { freeLeft: -1, balance: -1, charged: false, source: 'owner' }
  }

  const digest = await hmacHex(settings.telegramLink || 'x-compat', `${fp}|${brandRef}|${today()}`)
  const seenKey = `co:${fp}:${digest.slice(0, 32)}`
  const cached = await kvGet(env, seenKey)
  if (cached) {
    const c = JSON.parse(cached) as { freeLeft: number; balance: number; source: string }
    return { freeLeft: c.freeLeft, balance: c.balance, charged: false, source: c.source }
  }

  const r = await chargeOne(env, caller, fp, settings, ip(request),
    await fingerprintRotated(env, request, caller))
  const snap = { freeLeft: r.freeLeft, balance: r.balance, source: r.source }
  ctx.waitUntil(env.QUOTA.put(seenKey, JSON.stringify(snap), { expirationTtl: 2 * DAY })
    .catch(() => {}))
  return { ...snap, charged: true }
}

/**
 * أحداث تستحق انتباه المالك: محاولات تجاوز الحماية والاستنزاف.
 * تُستثنى الأحداث الروتينية (تسجيل دخول خاطئ، جهاز مختلف) لأنها لا تعني هجوماً
 * وتُغرق السجل فيصعب رؤية المهم.
 */
const ATTACK_REASONS = [
  'missing_signature', 'bad_signature', 'stale_signature', 'ip_hardban',
  'device_farm', 'device_mismatch', 'banned_device_hit', 'banned_ip_hit',
  'device_banned', 'ip_banned', 'non_owner_admin_attempt',
  'guest_token_device_mismatch',
  'bad_owner_key', 'scraping_suspected',
  // تجاوز الحدّ المضاعف عدة مرات يكفي للفت النظر، أما `rate_limited`
  // العادي فلا: مستخدم لم يغلق الشاشة، أو شبكة تتقطّع، أو تصفّح سريع —
  // كلها تبلغ الحدّ مرة أو مرتين ولا تعني هجوماً. كانت تظهر في اللوحة
  // كـ«هجوم» فتُنذر المالك على نفسه.
  'rate_limited_hard'
]

/**
 * الأحداث المشبوهة وحدها — ما يستحق نظر المالك.
 *
 * تبويب الأمان كان يعرض كل سطر في السجل: كلمة مرور منسيّة، تجاوز حدّ سرعة،
 * جهاز بدّل مستخدمه. الغرق في الضجيج يخفي الهجوم الحقيقي. هذه القائمة
 * تستبعد الخطأ البشري وتُبقي محاولات التجاوز والتزوير والعبث:
 *  - توقيع مفقود/مزوّر/قديم: طلب لا يأتي من التطبيق أصلاً.
 *  - device_farm: عنوان واحد بيفتح أجهزة كثيرة (تلاعب بالمنحة).
 *  - banned_*: محظور يعاود المحاولة بعد الحظر.
 *  - non_owner_admin_attempt: محاولة فتح لوحة المالك بلا صلاحية.
 *  - scraping_suspected: سحب بيانات آلي.
 */
const SUSPICIOUS_REASONS = [
  'missing_signature', 'bad_signature', 'stale_signature',
  'device_farm', 'banned_device_hit', 'banned_ip_hit',
  'device_banned', 'ip_banned', 'non_owner_admin_attempt',
  'guest_token_device_mismatch', 'bad_owner_key', 'scraping_suspected'
]


const COMPAT_TYPES = ['SCREEN', 'BATTERY', 'GLASS', 'INCASSABLE']

// حدود صارمة على مدخلات المالك: المالك موثوق، لكن جلسته قد تُسرق وحقول
// التوافقات تُخزَّن ثم تُرسل لكل مستخدم. الحجم المحدود يمنع صفّاً ضخماً
// يُثقل كل استجابة بحث، ويمنع كذلك تفجير حجم قاعدة D1 بأصفار قليلة.
const COMPAT_MAX_MODELS = 300
const COMPAT_MAX_MODEL_LEN = 80
const COMPAT_MAX_SUB_LEN = 60
const COMPAT_MAX_NOTE_LEN = 200

/**
 * يفصل نصّ الموديلات إلى قائمة. الفاصل هو السطر الجديد وحده.
 *
 * الفاصلة ليست فاصلاً: أسماء كثيرة تحملها أصلاً (`Redmi Note 8, 8 Pro`)،
 * فكان انشقاقها يخلق موديلين وهميين لا وجود لهما في الواقع. والقسمة تشمل
 * كل محارف الفصل في Unicode (`U+2028`/`U+2029`/`U+0085`) — وإلا مرّ سطر
 * يحمل أحدها كسطر واحد.
 */
function splitModelLines(raw: unknown): string[] {
  return String(raw ?? '')
    .split(/[\n\r\u2028\u2029\u0085]/)
    .map(s => s.replace(/[\u200b\u200e\u200f\ufeff]/g, '').trim().toLowerCase())
    .map(s => s.slice(0, COMPAT_MAX_MODEL_LEN))
    .filter(Boolean)
    .slice(0, COMPAT_MAX_MODELS)
}

/**
 * يُطبّع قائمة موديلات قادمة من العميل: يطبّق الحدود نفسها، ويرفض أي عنصر
 * ليس نصّاً. يُستعمل في `patch` أيضاً — وليس في `add` وحده — لأن مسار
 * `patch` كان يثق بـ`fields` كما وصلت، فجلسة مسروقة تستطيع تخطّي كل حدّ
 * عبر تمرير `compatibleModels` بلا فحص.
 */
function sanitizeModels(v: unknown): string[] {
  if (!Array.isArray(v)) return []
  return v.map(m => String(m).replace(/[\u200b\u200e\u200f\ufeff]/g, '').trim().toLowerCase())
    .map(s => s.slice(0, COMPAT_MAX_MODEL_LEN))
    .filter(Boolean)
    .slice(0, COMPAT_MAX_MODELS)
}

/**
 * يتحقق أن نوع القطعة معروف: إمّا من الأنواع الأصلية أو نوع أضافه المالك
 * نفسه (`kind='cat'`). نوع آخر تماماً = طلب مُلفَّق، لا مجرّد خطأ كتابة.
 */
async function assertCompatType(env: Env, brandFile: string, kind: string): Promise<string> {
  const k = String(kind ?? '').trim().toUpperCase().slice(0, 24)
  if (!k) throw new HttpError(400, 'نوع القطعة مطلوب')
  if (COMPAT_TYPES.includes(k)) return k
  const own = await env.XDB.prepare(
    `SELECT 1 x FROM x_compat_edits WHERE brand_file = ?1 AND kind = 'cat' AND deleted = 0`
  ).bind(brandFile).first<any>()
  if (own) {
    const rows = await env.XDB.prepare(
      `SELECT data FROM x_compat_edits WHERE brand_file = ?1 AND kind = 'cat' AND deleted = 0`
    ).bind(brandFile).all<{ data: string }>()
    for (const r of rows.results ?? []) {
      try {
        if (String(JSON.parse(r.data)?.name ?? '').toUpperCase() === k) return k
      } catch { /* صفّ نوع تالف لا يُسقط التحقق */ }
    }
  }
  throw new HttpError(400, 'نوع قطعة غير معروف')
}

/** شركات فرعية افتراضية — تُشتق قراءةً فقط من ملفات الشركات الأم، بلا أي كتابة على المصدر */
const VIRTUAL_SUB_BRANDS: { name: string; file: string; key: string }[] = [
  { name: 'redmi', file: '01xiaomi.json', key: 'redmi' },
  { name: 'poco', file: '01xiaomi.json', key: 'poco' },
  { name: 'oppo', file: '02realme.json', key: 'oppo' },
  { name: 'honor', file: '03huawei.json', key: 'honor' },
  { name: 'iqoo', file: '14vivo.json', key: 'iqoo' },
  // tecno مُدرَج في ملف إنفنكس (سجلات تحمل «tecno camon ..» ضمن
  // compatibleModels) ولا ملف مستقل له. نشتقّه قراءةً فقط: تصفية الكلمة
  // تُظهر سجلات تكنو وحدها من الملف المشترك، دون تعديل صفّ واحد في المصدر.
  { name: 'tecno', file: '05infinix.json', key: 'tecno' },
]

// ============================== Schematics catalog (READ-ONLY) ==============================

interface CatalogBrand { id: string; name: string }
interface CatalogModel { name: string; folders: { category: string; id: string }[] }
interface CatalogEntry { id: string; name: string; mimeType: string; size?: string | number }

async function cached<T>(env: Env, key: string, ttl: number, build: () => Promise<T>): Promise<T> {
  const hit = await env.QUOTA.get(key, 'json')
  if (hit) return hit as T
  const value = await build()
  await env.QUOTA.put(key, JSON.stringify(value), { expirationTtl: ttl })
  return value
}

async function readCatalogBrands(env: Env): Promise<CatalogBrand[]> {
  const obj = await env.SCHEMATICS.get(ROOT_CATALOG)
  if (!obj) return []
  const raw = await obj.json() as { id: string; name: string }[]
  return (Array.isArray(raw) ? raw : []).filter(b => typeof b?.id === 'string' && typeof b?.name === 'string')
}

async function readBrandCatalog(env: Env, brandId: string): Promise<{ models: CatalogModel[]; folders: Record<string, CatalogEntry[]> } | null> {
  const name = brandId.startsWith('r2:') ? brandId.slice(3) : brandId
  const obj = await env.SCHEMATICS.get(`catalog/v1/brands/${encodeURIComponent(name)}.json`)
  if (!obj) return null
  const data = await obj.json() as any
  return { models: data?.models ?? [], folders: data?.folders ?? {} }
}

/** شركات local/ (مثل Xiaomi/REDMI) — نفس منطق العامل الأصلي */
async function listLocalBrands(env: Env): Promise<CatalogBrand[]> {
  return cached(env, 'x_local_brands', 3600, async () => {
    const brands = new Map<string, CatalogBrand>()
    let cursor: string | undefined
    do {
      const page = await env.SCHEMATICS.list({ prefix: LOCAL_R2, limit: 1000, cursor, delimiter: '/' })
      for (const p of page.delimitedPrefixes ?? []) {
        let sub: string | undefined
        do {
          const sp = await env.SCHEMATICS.list({ prefix: p, limit: 1000, cursor: sub, delimiter: '/' })
          for (const s of sp.delimitedPrefixes ?? []) {
            const name = s.slice(p.length).replace(/\/$/, '')
            if (name && !brands.has(name)) {
              brands.set(name, { name, id: LOCAL_PREFIX + s.slice(LOCAL_R2.length).replace(/\/$/, '') })
            }
          }
          sub = sp.truncated ? sp.cursor : undefined
        } while (sub)
      }
      cursor = page.truncated ? page.cursor : undefined
    } while (cursor)
    return [...brands.values()].sort((a, b) => a.name.localeCompare(b.name))
  })
}

async function listLocalModels(env: Env, brandId: string): Promise<CatalogModel[]> {
  const prefix = LOCAL_R2 + brandId.slice(LOCAL_PREFIX.length) + '/'
  return cached(env, `x_lm:${brandId}`, 3600, async () => {
    const models = new Map<string, CatalogModel>()
    let cursor: string | undefined
    do {
      const page = await env.SCHEMATICS.list({ prefix, limit: 1000, cursor, delimiter: '/' })
      for (const p of page.delimitedPrefixes ?? []) {
        const name = p.slice(prefix.length).replace(/\/$/, '')
        if (name) models.set(name, { name, folders: [{ category: 'Hardware', id: LOCAL_PREFIX + p.slice(LOCAL_R2.length).replace(/\/$/, '') }] })
      }
      cursor = page.truncated ? page.cursor : undefined
    } while (cursor)
    return [...models.values()].sort((a, b) => a.name.localeCompare(b.name))
  })
}

const EXT_MIME: Record<string, string> = {
  pdf: 'application/pdf', svg: 'image/svg+xml', png: 'image/png',
  jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp'
}

async function listLocalFiles(env: Env, folderId: string): Promise<CatalogEntry[]> {
  const prefix = LOCAL_R2 + folderId.slice(LOCAL_PREFIX.length) + '/'
  return cached(env, `x_lf:${folderId}`, 3600, async () => {
    const entries: CatalogEntry[] = []
    let cursor: string | undefined
    do {
      const page = await env.SCHEMATICS.list({ prefix, limit: 1000, cursor, delimiter: '/' })
      for (const p of page.delimitedPrefixes ?? []) {
        const name = p.slice(prefix.length).replace(/\/$/, '')
        if (name) entries.push({ name: `${name} /`, id: LOCAL_PREFIX + p.slice(LOCAL_R2.length).replace(/\/$/, ''), mimeType: FOLDER_MIME })
      }
      for (const o of page.objects ?? []) {
        const name = o.key.slice(prefix.length).replace(/%2F/gi, '/')
        if (name) entries.push({ name, id: LOCAL_PREFIX + o.key.slice(LOCAL_R2.length), mimeType: EXT_MIME[name.split('.').pop()?.toLowerCase() ?? ''] ?? 'application/octet-stream', size: String(o.size) })
      }
      cursor = page.truncated ? page.cursor : undefined
    } while (cursor)
    return entries
  })
}
// ============================== أكاديمية الدورات ==============================
//
// الأمان هنا مبني على طبقتين مستقلتين، ونجاح أي منهما وحده لا يكفي:
//   1. توقيع الطلب (x-app-sig) — Ed25519 بمفتاح خاص بكل تثبيت. يمنع أي
//      سكربت خارجي من لمس المسارات، ولا سرّ مشترك في الحزمة يُستخرج.
//   2. الاستحقاق — يُحسب من x_course_grants بمفتاح `install_id` الموثّق
//      بالتوقيع، لا بمعرّف جهاز يرسله العميل.
// وكل مسار يقرأ الاستحقاق من الخادم لا من الطلب، فالتلاعب بالعميل لا يفتح شيئاً.
//
// ملاحظة عن التشفير: كان كل ملف يُخدَم مشفراً بـ AES-CTR بمفتاح مضمّن في
// التطبيق. ذلك لم يكن عزلاً: المفتاح نفسه في كل نسخة، ومن استخرجه فكّ كل
// ملف. أُزيل التشفير على مستوى التطبيق، والملفات تُخدَم كما هي عبر TLS.
// العزل الفعلي يأتي من دلو R2 منفصل (XLEARN) ومن حصر الوصول بتوقيع موثّق.

/** يجزّئ كود المفتاح — القاعدة تحفظ البصمة لا الكود. */
async function keyHash(code: string): Promise<string> {
  const norm = code.trim().toUpperCase().replace(/[\s-]/g, '')
  const digest = await crypto.subtle.digest(
    'SHA-256', new TextEncoder().encode(`xapp-course-key-v1|${norm}`))
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('')
}

/** يولّد كوداً مقروءاً: مجموعات من 4 محارف بلا أحرف ملتبسة (0/O، 1/I/L). */
function makeKeyCode(): string {
  const alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
  const bytes = new Uint8Array(20)
  crypto.getRandomValues(bytes)
  let out = ''
  for (let i = 0; i < 20; i++) {
    out += alphabet[bytes[i] % alphabet.length]
    if (i % 4 === 3 && i !== 19) out += '-'
  }
  return out
}

/**
 * استحقاق الجهاز لدورة: مفتوحة (locked=0) للجميع، أو موجودة في سجل المنح.
 *
 * الربط بالجهاز لا بالحساب عن قصد: إنشاء حساب جديد على الجهاز نفسه لا
 * يمنح دورةً ثانية، وإعادة تثبيت التطبيق على جهاز آخر لا تنقل المفتاح.
 */
async function courseUnlocked(env: Env, installId: string, courseId: string): Promise<boolean> {
  const course = await env.XDB
    .prepare('SELECT locked FROM x_courses WHERE id = ?1 AND published = 1')
    .bind(courseId).first<{ locked: number }>()
  if (!course) return false
  // دورة غير مقفلة أصلاً: لا كود عليها، فكل فيديو غير موسوم «مجاني» مباح.
  if (!course.locked) return true
  // لا تثبيت موثّقاً يعني لا استحقاق: الطلب غير موقّع أصلاً في هذه الحالة.
  if (!installId) return false
  const grant = await env.XDB
    .prepare('SELECT 1 x FROM x_course_grants WHERE install_id = ?1 AND course_id = ?2')
    .bind(installId, courseId).first<{ x: number }>()
  return !!grant
}

/**
 * تثبيت المالك: أي تثبيت فُتحت عليه لوحة المالك بنجاح.
 *
 * هذا هو ما يصنع استحقاق المالك الحقيقي، لا وجود رمز جلسة في الطلب. لو
 * اعتمدنا على `role === 'owner'` وحده لكان المالك يرى دوراته المقفلة مفتوحة
 * على أي جهاز يسجّل فيه بحسابه العادي — وهو بالضبط ما جعل القفل يبدو معطلاً.
 *
 * المفتاح هو `installId` الموثّق بالتوقيع، لا معرّف الجهاز المرسل في ترويسة.
 * كان الوسم يُنسب إلى `x-device-id`، وهو ما جعل الانتحال ممكناً: من وقّع
 * طلباً بمفتاحه الخاص ثم وضع معرّف جهاز المالك صار مالكاً. الآن لا يُشتقّ
 * الوسم من شيء يملك العميل تغييره.
 *
 * الوسم صريح في قاعدة البيانات ولا يُشتقّ من الدور: منحه يحتاج مفتاح المالك.
 */
async function ownerDevice(env: Env, installId: string): Promise<boolean> {
  if (!installId) return false
  const row = await env.XDB
    .prepare('SELECT 1 x FROM x_devices WHERE install_id = ?1 AND owner_marked = 1')
    .bind(installId).first<{ x: number }>()
  return !!row
}

/** يوسم التثبيت الحالي كتثبيت مالك. يُنادى بعد دخول اللوحة بنجاح. */
async function markOwnerDevice(env: Env, installId: string, deviceId: string): Promise<void> {
  if (!installId) return
  const now = new Date().toISOString()
  try {
    // الصف مفتاحه install_id: التثبيت وحدة مستقلة. device_id يُكتب للعرض
    // في اللوحة فقط، ولا يُقرأ منه استحقاق.
    await env.XDB.prepare(
      `INSERT INTO x_devices (install_id, device_id, owner_marked, first_seen, last_seen)
       VALUES (?1, ?2, 1, ?3, ?3)
       ON CONFLICT(install_id) DO UPDATE SET owner_marked = 1, last_seen = ?3`
    ).bind(installId, deviceId, now).run()
  } catch { /* الوسم ليس شرطاً لدخول اللوحة */ }
}

/**
 * أجهزة المالك المسجّلة.
 *
 * المالك يدخل من أي هاتف يريد — هذا شرط أساسي لا نتنازل عنه. الأمان يجيء من
 * الحدّ: كل هاتف جديد يُسجَّل، والعدد مسقوف. فمن سرق كلمة المرور لا يفتح
 * اللوحة من أي جهاز في العالم، بل يصطدم بسقف يلاحظه المالك في السجل.
 * الحدّ لا يحمي كلمة المرور وحدها بل يجعل الاختراق مرئياً لا صامتاً.
 */
const MAX_OWNER_DEVICES = 3

async function ownerDevices(env: Env): Promise<string[]> {
  try {
    const rows = await env.XDB
      .prepare('SELECT install_id FROM x_devices WHERE owner_bound = 1 ORDER BY last_seen DESC')
      .all<{ install_id: string }>()
    return (rows.results ?? []).map(r => r.install_id).filter(Boolean)
  } catch {
    return []
  }
}

async function registerOwnerDevice(env: Env, installId: string, deviceId: string): Promise<void> {
  if (!installId) return
  const now = new Date().toISOString()
  await env.XDB.prepare(
    `INSERT INTO x_devices (install_id, device_id, owner_marked, owner_bound, first_seen, last_seen)
     VALUES (?1, ?2, 1, 1, ?3, ?3)
     ON CONFLICT(install_id) DO UPDATE SET owner_marked = 1, owner_bound = 1, last_seen = ?3`
  ).bind(installId, deviceId, now).run()
}

/** يفرّغ خانة: يسحب ربط التثبيت ووسمه معاً. */
async function releaseOwnerDevice(env: Env, installId: string): Promise<void> {
  if (!installId) return
  await env.XDB.prepare(
    'UPDATE x_devices SET owner_marked = 0, owner_bound = 0 WHERE install_id = ?1'
  ).bind(installId).run()
}

// ---------- روابط بثّ موقّعة للدروس ----------
// مشغّل الفيديو لا يستطيع إرسال ترويسات توقيع مخصّصة في كل طلب قطعة،
// والوكيل المحلي كان حلقة فشل كاملة تُعلّق `initialize()` على الشبكات
// الضعيفة. بدلاً منه يُصدر الخادم رابطاً موقّعاً بـHMAC قصير العمر داخل
// ردّ الدورات الموقَّع أصلاً — يُثبت أنه وُلّد بعد فحص الاستحقاق، ويتحقق
// معالج البثّ منه قبل قراءة أي بايت من R2. البثّ يذهب من Cloudflare إلى
// المشغّل مباشرة: أقصر مسار ممكن وأسرع بداية على أي شبكة.
const LEARN_STREAM_TTL = 6 * 3600 * 1000

/**
 * يقطّع تياراً إلى المدى المطلوب: يتجاوز `start` بايت ثم يمرّر `span` بايت.
 *
 * لماذا نقطّع بدل جلب مدى من R2؟ لأن المصدر قد يكون ردّاً من كاش الحافة —
 * الردّ الكامل المخزَّن يُقرأ بسرعة الشبكة الداخلية، والمشغّل لا يستقبل
 * إلا المدى الذي طلبه. تجاوز البايتات داخل العامل عملية إدخال/إخراج لا
 * حساب، فلا تُستهلك حصة المعالج.
 */
function sliceStream(
  body: ReadableStream<Uint8Array>, start: number, span: number
): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    async start(controller) {
      const reader = body.getReader()
      let skip = start, left = span
      try {
        while (left > 0) {
          const { done, value } = await reader.read()
          if (done) break
          let chunk = value
          if (skip > 0) {
            if (chunk.byteLength <= skip) { skip -= chunk.byteLength; continue }
            chunk = chunk.subarray(skip)
            skip = 0
          }
          const part = chunk.byteLength > left ? chunk.subarray(0, left) : chunk
          left -= part.byteLength
          controller.enqueue(part)
        }
        controller.close()
      } catch (e) {
        controller.error(e)
      } finally {
        reader.releaseLock()
      }
    },
    cancel() { body.cancel() },
  })
}

let _learnKey: Promise<CryptoKey> | null = null
function learnHmacKey(env: Env): Promise<CryptoKey> {
  _learnKey ??= crypto.subtle.importKey('raw',
    new TextEncoder().encode(`learn-stream|${env.X_JWT_SECRET}`),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify'])
  return _learnKey
}

/** رمز بثّ لفيديو على تثبيت بعينه حتى انتهاء `exp`. */
async function learnToken(env: Env, videoId: string, installId: string,
                          exp: number): Promise<string> {
  const sig = await crypto.subtle.sign('HMAC', await learnHmacKey(env),
    new TextEncoder().encode(`${videoId}|${installId}|${exp}`))
  return Array.from(new Uint8Array(sig), b => b.toString(16).padStart(2, '0')).join('')
}

/** طلب بثّ يحمل رمزاً في الرابط بدل ترويسات التوقيع. */
function learnTokenRequest(request: Request): boolean {
  if (request.method !== 'GET') return false
  const u = new URL(request.url)
  return /^\/v1\/learn\/stream\/[\w-]{1,64}$/.test(u.pathname) &&
    u.searchParams.has('s') && u.searchParams.has('i') && u.searchParams.has('e')
}

/** يتحقق من رمز البثّ ويعيد installId الذي صدر له — بلا ثقة بأي ترويسة. */
async function verifyLearnToken(env: Env, request: Request,
                                videoId: string): Promise<string | null> {
  const u = new URL(request.url)
  const s = u.searchParams.get('s') ?? ''
  const inst = u.searchParams.get('i') ?? ''
  const e = Number(u.searchParams.get('e') ?? 0)
  if (!/^[0-9a-f]{64}$/.test(s) || !/^[\w:-]{6,80}$/.test(inst) || e <= Date.now()) {
    return null
  }
  const ok = await crypto.subtle.verify('HMAC', await learnHmacKey(env),
    hexToBytes(s), new TextEncoder().encode(`${videoId}|${inst}|${e}`))
  return ok ? inst : null
}

/**
 * شكل الفيديو كما يراه العميل.
 *
 * الفيديو المقفل يُرسل بلا أي بيانات وصفية: لا مفتاح تخزين ولا مدّة ولا
 * حجم ولا رابط بث — حتى عدد الثواني يمكن أن يُعاد بناؤه لاحقاً. يُرسل فقط
 * ما تحتاجه الواجهة لرسم قفل. هذا ما يجعل الشاشة آمنة ولو سُرّبت الاستجابة.
 */
function videoView(v: any, unlocked: boolean, hidden = false, streamUrl = '') {
  // مفتاح الإيقاف: عند تفعيله لا يُبنى أي رابط بثّ لأي فيديو، ولا يبقى
  // `playable` صحيحاً. الحجب هنا لا في الواجهة كي لا يُبثّ الملف أصلاً —
  // نسخة قديمة من التطبيق لا تعرف المفتاح تتعطّل معه بلا تحديث.
  const canPlay = unlocked && !hidden
  const base = {
    id: v.id,
    title: v.title,
    description: unlocked ? (v.description ?? '') : '',
    mode: v.mode,
    sort: v.sort,
    durationS: unlocked ? (v.duration_s ?? 0) : 0,
    sizeBytes: unlocked ? (v.size_bytes ?? 0) : 0,
    playable: canPlay,
    // المصغّرة تُرسل للمقفل أيضاً: بدونها تصير كل بطاقة رمادية، والمستخدم
    // لا يميّز درساً من آخر فيقرر على العمى. رؤية الصورة لا تكشف المقطع.
    thumbUrl: v.thumb_key ? `/v1/learn/thumb/${v.id}` : '',
  }
  // الرابط لا يُبنى إلا لفيلم مباح — لا وجود له في ردّ المقفل إطلاقاً.
  // `streamUrl` يحمل رمزاً موقّعاً يفتح البثّ مباشرة من Cloudflare بدعم
  // Range — بلا وسيط محلي ولا ترويسات مخصّصة من المشغّل.
  return canPlay
    ? { ...base, streamUrl: streamUrl || `/v1/learn/stream/${v.id}` }
    : base
}

/** يبني قائمة الدورات مع فلترة ما هو معروض للعميل حسب استحقاقه.
 *
 * `isOwner` استثناء جوهري: المالك ينشئ الدورات ولا يدخل لها كوداً، فلو
 * خضع لقاعدة الاستحقاق لظهرت دوراته المقفلة أمامه بلا رابط بثّ — أي أن
 * معاينته لعمله كانت ستعلق على «جار التحميل» للأبد. المالك يرى ما يملك.
 */
async function coursesFor(env: Env, installId: string, isOwner = false,
                          videosHidden = false) {
  const courses = await env.XDB.prepare(
    `SELECT id, title, subtitle, description, cover_key, locked, sort
     FROM x_courses WHERE published = 1 ORDER BY sort, created_at DESC`
  ).all<any>()
  const videos = await env.XDB.prepare(
    `SELECT id, course_id, title, description, mode, sort, duration_s, size_bytes, thumb_key
     FROM x_course_videos WHERE published = 1 ORDER BY sort, created_at`
  ).all<any>()

  const granted = new Set<string>()
  if (installId) {
    const rows = await env.XDB
      .prepare('SELECT course_id FROM x_course_grants WHERE install_id = ?1')
      .bind(installId).all<{ course_id: string }>()
    for (const r of rows.results ?? []) granted.add(r.course_id)
  }

  const byCourse = new Map<string, any[]>()
  for (const v of videos.results ?? []) {
    const list = byCourse.get(v.course_id) ?? []
    list.push(v)
    byCourse.set(v.course_id, list)
  }

  // رمز بثّ لكل فيديو قد يُعرض لهذا التثبيت: مجاني دائماً، أو في دورة
  // مُستحَقّة أو على جهاز المالك. لا يُسكّ رمز لفيديو لن يصل العميل رابطه
  // أصلاً — الرموز حِكر على الاستحقاق مثل الروابط تماماً.
  const exp = Date.now() + LEARN_STREAM_TTL
  const toks = new Map<string, string>()
  const need: any[] = []
  for (const c of courses.results ?? []) {
    if (!c.locked || granted.has(c.id) || isOwner) {
      need.push(...(byCourse.get(c.id) ?? []))
      continue
    }
    for (const v of byCourse.get(c.id) ?? []) {
      if (v.mode === 'free') need.push(v)
    }
  }
  await Promise.all(need.map(async v =>
    toks.set(v.id, await learnToken(env, v.id, installId, exp))))

  return (courses.results ?? []).map(c => {
    const unlocked = !c.locked || granted.has(c.id) || isOwner
    const list = byCourse.get(c.id) ?? []
    // في دورة مقفلة: الفيديو المجاني (mode=free) يبقى مفتوحاً — هذا هو
    // «عرض مجاني» الذي يشتري به المالك ثقة المستخدم. والباقي مقفل.
    return {
      id: c.id,
      title: c.title,
      subtitle: c.subtitle ?? '',
      description: unlocked ? (c.description ?? '') : '',
      coverUrl: c.cover_key ? `/v1/learn/cover/${c.id}` : '',
      locked: !!c.locked,
      unlocked,
      videoCount: list.length,
      freeCount: list.filter(v => v.mode === 'free').length,
      videos: list.map(v => {
        const playable = (v.mode === 'free' || unlocked) && !videosHidden
        const tok = playable ? toks.get(v.id) : undefined
        const url = tok ? `/v1/learn/stream/${v.id}?i=${installId}&e=${exp}&s=${tok}` : ''
        return videoView(v, v.mode === 'free' || unlocked, videosHidden, url)
      }),
    }
  })
}

// ============================== Announcements ==============================

async function announcements(env: Env): Promise<unknown[]> {
  // إعلانات تطبيق X وحدها — لا تُدمج إعلانات أي تطبيق آخر.
  // الدمج السابق مع مرآة phonex كان يعرض إعلانات تطبيق آخر داخل X، ويجعل
  // تغيير إعلاناته يظهر هنا بلا علم المالك. الآن كل تطبيق مستقل بإعلاناته.
  const rows = await env.XDB
    .prepare('SELECT id, data FROM x_announcements ORDER BY id DESC LIMIT 100')
    .all<{ id: string; data: string }>()
  return (rows.results ?? [])
    .map(r => ({ id: r.id, ...JSON.parse(r.data) }))
    .filter((a: any) => a.active === true)
    .sort((a: any, b: any) => (b.order ?? 0) - (a.order ?? 0))
}

/**
 * حدّ محاولات دخول المالك — مفتاحه الحساب لا الجهاز.
 *
 * حدّ الجهاز وحده لا يكفي: مهاجم يبدّل الأجهزة والعناوين يجرّب بلا حد.
 * العدّاد على `owner` عالمي، فسقفه يحمي الحساب من أي مصدر كان.
 */
const OWNER_LOCK_BUCKET = 'ownerlogin'

async function ownerLoginGuard(env: Env): Promise<void> {
  const used = Number(await kvGet(env, `rl:${OWNER_LOCK_BUCKET}`)) || 0
  if (used >= 8) {
    throw new HttpError(429, 'تم إيقاف محاولات الدخول مؤقتاً — حاول بعد 15 دقيقة')
  }
}

async function noteOwnerLoginFail(env: Env, request: Request): Promise<void> {
  const key = `rl:${OWNER_LOCK_BUCKET}`
  const used = Number(await kvGet(env, key)) || 0
  await env.QUOTA.put(key, String(used + 1), { expirationTtl: 900 })
  await logSecurity(env, request, 'bad_owner_login', `attempt=${used + 1}`)
}

async function clearOwnerLoginFails(env: Env): Promise<void> {
  try { await env.QUOTA.delete(`rl:${OWNER_LOCK_BUCKET}`) } catch { /* لا يمنع الدخول */ }
}

/**
 * جلسة المالك — منفصلة عن جلسات المستخدمين بسرّ مستقل و`typ` مميز.
 *
 * الفصل يمنع أخطر سيناريو: تزوير جلسة عادية بحقل `role=owner`. جلسات
 * المستخدمين تُوقّع بـ X_JWT_SECRET، وجلسات المالك بـ X_OWNER_JWT_SECRET
 * (يسقط للسرّ العام إن لم يُضبط، فتبقى النسخة تعمل). أي رمز لا يحمل
 * `typ=owner` مرفوض حتى لو صحّ توقيعه.
 */
function ownerSecret(env: Env): string {
  return env.X_OWNER_JWT_SECRET || env.X_JWT_SECRET
}

async function signOwnerJwt(env: Env, payload: Record<string, unknown>, ttl: number): Promise<string> {
  return signJwt({ ...payload, typ: 'owner' }, ownerSecret(env), ttl)
}

async function verifyOwnerJwt(env: Env, token: string): Promise<Record<string, any>> {
  const payload = await verifyJwt(token, ownerSecret(env))
  if (payload.typ !== 'owner' || payload.role !== 'owner') {
    throw new HttpError(401, 'invalid token')
  }
  return payload
}

/** يُرجع الحمولة إن كان الرمز جلسة مالك صالحة، وإلا null بلا رمي خطأ. */
async function tryOwnerToken(env: Env, token: string): Promise<Record<string, any> | null> {
  try {
    return await verifyOwnerJwt(env, token)
  } catch {
    return null
  }
}

// ============================== Chat ==============================

/**
 * الدردشة: مجموعة مجتمعية واحدة بأقسام — لا رسائل خاصة بين الأفراد.
 *
 * لماذا لا خاص؟ الخاص يحتاج تشفيراً طرفياً وإدارة مفاتيح، ووعداً أمنياً لا
 * يستطيع خادم واحد تحقيقه. الاختيار الصريح: كل رسالة علنية داخل قسم، وهذا
 * ما يمكن حمايته فعلاً (تصفية، كتم، طرد، سجل).
 */
const CHAT_KINDS = ['text', 'image', 'audio', 'video', 'system'] as const
type ChatKind = typeof CHAT_KINDS[number]

/** أنواع الوسائط التي يُقبل رفعها، والتحقق من بايتها السحرية لا من ادّعاء العميل. */
/** نوع وسيط مكتشَف. `test` غائب في نتائج التفريع الداخلي (عائلة MP4). */
interface MediaSig {
  kind: 'image' | 'audio' | 'video'
  ext: string
  mime: string
  test?: (b: Uint8Array) => boolean
}

const MEDIA_SIGNATURES: MediaSig[] = [
  { kind: 'image', ext: 'png', mime: 'image/png', test: b => b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 },
  { kind: 'image', ext: 'jpg', mime: 'image/jpeg', test: b => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { kind: 'image', ext: 'gif', mime: 'image/gif', test: b => b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 },
  { kind: 'image', ext: 'webp', mime: 'image/webp', test: b => b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50 },
  // فحص webm قبل mkv: الترويسة نفسها، والفرق في نوع المحتوى داخل الملف.
  { kind: 'video', ext: 'webm', mime: 'video/webm', test: b => b[0] === 0x1a && b[1] === 0x45 && b[2] === 0xdf && b[3] === 0xa3 },
  // عائلة MP4 (mp4/3gp/m4a) لا تُفحص هنا: علامتها واحدة `ftyp`، والتمييز
  // يحتاج قراءة العلامة الداخلية ومسارات الملف — انظر sniffMp4Family.
  { kind: 'audio', ext: 'ogg', mime: 'audio/ogg', test: b => b[0] === 0x4f && b[1] === 0x67 && b[2] === 0x67 && b[3] === 0x53 },
  { kind: 'audio', ext: 'wav', mime: 'audio/wav', test: b => b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x41 && b[10] === 0x56 && b[11] === 0x45 },
  { kind: 'audio', ext: 'mp3', mime: 'audio/mpeg', test: b => b[0] === 0x49 && b[1] === 0x44 && b[2] === 0x33 },
  { kind: 'audio', ext: 'mp3', mime: 'audio/mpeg', test: b => b[0] === 0xff && (b[1] & 0xe0) === 0xe0 },
  { kind: 'audio', ext: 'aac', mime: 'audio/aac', test: b => b[0] === 0xff && (b[1] & 0xf6) === 0xf0 },
]

/**
 * يتحقق أن البايتات وسيط فعلي ويُعيد نوعه وامتداده.
 *
 * الاعتماد على نوع يرسله العميل كان يسمح برفع أي ملف (سكريبت HTML مثلاً)
 * وتخزينه بامتداد صورة، فيصبح رابطاً يُخدَم بترويسة صورة مزيفة. الفحص هنا
 * يجعل ما يُخزَّن وسيطاً حقيقياً فقط.
 */
function sniffMedia(bytes: Uint8Array): MediaSig | null {
  if (bytes.length < 16) return null
  if (bytes[4] === 0x66 && bytes[5] === 0x74 && bytes[6] === 0x79 && bytes[7] === 0x70) {
    return sniffMp4Family(bytes)
  }
  for (const s of MEDIA_SIGNATURES) if (s.test?.(bytes)) return s
  return null
}

/**
 * يميّز داخل عائلة MP4 بين فيديو و3gp وصوت m4a.
 *
 * كلها تشترك في علامة `ftyp` عند البايت الرابع، فترتيب الجدول وحده كان
 * يجعل أول قاعدة mp4 تلتقط كل ملفات m4a أيضاً — أي أن كل رسالة صوتية
 * سُجّلت من التطبيق خُزّنت كـ«فيديو»، فعُرضت بمشغّل فيديو بدل موجة صوتية.
 * التمييز الصحيح: العلامة الداخلية (bytes 8..11) ثم وجود مسار فيديو `vide`
 * داخل الملف؛ ملف صوتي لا مسار فيديو فيه.
 */
function sniffMp4Family(bytes: Uint8Array): MediaSig {
  const brand = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11])
  const audioBrand = brand === 'M4A ' || brand === 'M4B ' ||
    brand === 'M4P ' || brand === 'F4A '
  const is3gp = brand.startsWith('3gp') || brand.startsWith('3g2')
  // مسارات الملف تكون في `moov`، وهو إمّا في مقدّمة الملف (faststart) أو في
  // آخر. نفحص الطرفين فقط بدل فكّ الملف كله: يكفي للتمييز ويظل رخيصاً على
  // المقاطع الكبيرة. فكّ latin1 يكفي لمقارنة ASCII بلا تحقق UTF-8.
  const dec = new TextDecoder('latin1')
  const edge = 64 * 1024
  const head = dec.decode(bytes.subarray(0, Math.min(edge, bytes.length)))
  const tail = bytes.length > edge
    ? dec.decode(bytes.subarray(Math.max(0, bytes.length - edge)))
    : ''
  const hasVideo = head.includes('vide') || tail.includes('vide')
  const hasAudio = head.includes('soun') || tail.includes('soun')

  if (hasVideo) {
    return is3gp
      ? { kind: 'video', ext: '3gp', mime: 'video/3gpp' }
      : { kind: 'video', ext: 'mp4', mime: 'video/mp4' }
  }
  if (hasAudio || audioBrand || is3gp) {
    return { kind: 'audio', ext: 'm4a', mime: 'audio/mp4' }
  }
  // بلا مسار ظاهر — الغالب في مقاطع الجوال فيديو، وهذا الاحتياط يحفظ
  // السلوك القديم بدل رفض الملف.
  return audioBrand
    ? { kind: 'audio', ext: 'm4a', mime: 'audio/mp4' }
    : { kind: 'video', ext: 'mp4', mime: 'video/mp4' }
}

/** تنقية النص: نحذف محارف التحكم وعلامات الاتجاه المزيفة. */
function cleanText(raw: unknown, max: number): string {
  return String(raw ?? '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .replace(/[\u202A-\u202E\u2066-\u2069]/g, '')
    .trim()
    .slice(0, max)
}

interface ChatProfile { user_id: string; nickname: string; avatar_key: string; notify: number }

async function chatProfiles(XDB: D1Database, ids: string[]): Promise<Map<string, ChatProfile>> {
  const out = new Map<string, ChatProfile>()
  const uniq = [...new Set(ids.filter(Boolean))].slice(0, 200)
  if (!uniq.length) return out
  // استعلام واحد بقائمة معاملات: بديل الاستعلام لكل مستخدم كان يضرب حدّ
  // استعلامات D1 في قسم نشط بسرعة.
  const ph = uniq.map((_, i) => `?${i + 1}`).join(',')
  const res = await XDB.prepare(
    `SELECT user_id, nickname, avatar_key, notify FROM x_chat_profiles WHERE user_id IN (${ph})`
  ).bind(...uniq).all<ChatProfile>()
  for (const r of res.results ?? []) out.set(r.user_id, r)
  return out
}

/** إجراءات المالك الفعّالة على مستخدم — كتم سارٍ وطرد غير منتهٍ. */
async function chatRestriction(env: Env, userId: string, roomId: string): Promise<{
  muted: boolean; kicked: boolean; reason: string; until: number
}> {
  const now = Date.now()
  const rows = await env.XDB.prepare(
    `SELECT kind, room_id, reason, until FROM x_chat_actions WHERE user_id = ?1`
  ).bind(userId).all<{ kind: string; room_id: string; reason: string; until: number }>()
  let muted = false, kicked = false, reason = '', until = 0
  for (const r of rows.results ?? []) {
    // room_id فارغ = يسري على كل الأقسام
    if (r.room_id && r.room_id !== roomId) continue
    // until === 0 يعني بلا نهاية، للنوعين.
    const live = r.until === 0 || r.until > now
    if (!live) continue
    if (r.kind === 'mute') { muted = true; if (r.until > until) until = r.until }
    if (r.kind === 'kick') { kicked = true; if (r.until > until) until = r.until }
    if (r.reason) reason = r.reason
  }
  return { muted, kicked, reason, until }
}

/** مشتركون فعلاً: اشتراك سارٍ (expires_at مستقبلي) أو بلا انتهاء. */
function isSubscriber(user: XUser | null): boolean {
  if (!user) return false
  if (user.role === 'owner') return true
  return user.expires_at === 0 || user.expires_at > Date.now()
}

/**
 * من يستطيع الكتابة؟ قرار واحد في مكان واحد.
 *
 * كان الفحص موزّعاً في كل مسار، وأي مسار جديد ينسى فحصاً يفتح ثغرة. هنا
 * تُرجع السبب أيضاً، فيظهر للمستخدم منع مفهوم لا خطأ غامض.
 */
function chatWriteAllowed(
  settings: XSettings, caller: Caller, user: XUser | null,
): { ok: boolean; reason: string } {
  if (caller.role === 'owner') return { ok: true, reason: '' }
  if (settings.chatReadOnly) return { ok: false, reason: 'الدردشة في وضع القراءة فقط' }
  // «all» تعني الجميع بمن فيهم الزوار. هذا الفحص يجب أن يسبق شرط وجود
  // الحساب: كان الشرط يتوقف قبله، فيُمنع الزائر ولو اختار المالك «الجميع»
  // صراحةً — وهو ما يجعل السماح في اللوحة بلا أثر.
  if (settings.chatWriteScope === 'all') return { ok: true, reason: '' }
  if (!user) return { ok: false, reason: 'أنشئ حساباً للمشاركة في الدردشة' }
  if (!user.active) return { ok: false, reason: 'الحساب بانتظار تفعيل المالك' }
  if (settings.chatWriteScope === 'subscribers' && !isSubscriber(user)) {
    return { ok: false, reason: 'الكتابة للمشتركين فقط — تواصل مع المالك' }
  }
  return { ok: true, reason: '' }
}

/** من يرسل صوتاً/فيديو؟ المالك، والمشتركون السارون فقط. */
function chatMediaAllowed(
  settings: XSettings, caller: Caller, user: XUser | null,
): { ok: boolean; reason: string } {
  if (caller.role === 'owner') return { ok: true, reason: '' }
  if (settings.chatMediaScope === 'none') {
    return { ok: false, reason: 'إرسال المقاطع موقوف حالياً' }
  }
  if (!isSubscriber(user)) {
    return { ok: false, reason: 'الصوت والفيديو للمشتركين السارين فقط' }
  }
  return { ok: true, reason: '' }
}

/** شكل الرسالة كما تُرسل للتطبيق — يُبنى في مكان واحد. */
function chatMessageJson(
  m: {
    id: string; room_id: string; user_id: string; kind: string
    body: string; media_key: string; media_mime: string; media_size: number
    created_at: number; waveform?: string; media_seconds?: number
    reply_to?: string; reply_to_body?: string; reply_to_name?: string
    reply_to_kind?: string
  },
  p: ChatProfile | undefined,
  meId: string,
): Record<string, unknown> {
  return {
    id: m.id,
    roomId: m.room_id,
    kind: m.kind,
    body: m.body,
    mediaUrl: m.media_key ? `/v1/media/${m.media_key}` : '',
    mediaMime: m.media_mime,
    mediaSize: m.media_size,
    // مخطط الموجة يُرسل كسلسلة أرقام مفصولة بفواصل ويُفكّ في التطبيق.
    // الصيغة النصّية توفّر تحويلات JSON لعشرات الأرقام في كل رسالة صوتية.
    waveform: m.waveform ?? '',
    seconds: m.media_seconds ?? 0,
    // الردّ: معرّف الرسالة المقتبسة ومقتطف منها. المقتطف مُضمَّن في الردّ
    // نفسه كي لا يحتاج العميل نداءً آخر لجلب سياق ردّ قديم خارج الصفحة.
    replyTo: m.reply_to ?? '',
    replyPreview: m.reply_to
      ? {
          id: m.reply_to,
          body: m.reply_to_body ?? '',
          kind: m.reply_to_kind ?? 'text',
          nickname: m.reply_to_name ?? '',
        }
      : null,
    at: m.created_at,
    mine: m.user_id === meId,
    author: {
      id: m.user_id,
      nickname: p?.nickname || '',
      avatarUrl: p?.avatar_key ? `/v1/media/${p.avatar_key}` : '',
    },
  }
}

/**
 * المشاهدون لكل رسالة — من تجاوز ختمه الزمني زمن الرسالة.
 *
 * التخزين ختم واحد لكل (مستخدم، قسم) لا صف لكل مشاهدة: كلفة الكتابة تبقى
 * ثابتة مهما كثرت الرسائل، والقراءة استعلام صغير واحد. الصور تُعرض حتى 8
 * مشاهدين فقط — قائمة أطول لا تُقرأ على شاشة جوال.
 */
async function chatSeers(
  env: Env, roomId: string, times: number[], excludeId: string,
): Promise<Map<number, { id: string; nickname: string; avatarUrl: string }[]>> {
  const out = new Map<number, { id: string; nickname: string; avatarUrl: string }[]>()
  if (!times.length) return out
  const min = Math.min(...times)
  const rows = await env.XDB.prepare(
    `SELECT user_id, last_at FROM x_chat_seen
     WHERE room_id = ?1 AND last_at >= ?2 AND user_id <> ?3
     ORDER BY last_at DESC LIMIT 200`
  ).bind(roomId, min, excludeId).all<{ user_id: string; last_at: number }>()
  const seen = rows.results ?? []
  if (!seen.length) return out
  const profiles = await chatProfiles(env.XDB, seen.map(s => s.user_id))
  for (const t of times) {
    const list = seen
      .filter(s => s.last_at >= t)
      .slice(0, 8)
      .map(s => {
        const p = profiles.get(s.user_id)
        return {
          id: s.user_id,
          nickname: p?.nickname || '',
          avatarUrl: p?.avatar_key ? `/v1/media/${p.avatar_key}` : '',
        }
      })
    out.set(t, list)
  }
  return out
}

/**
 * إحصاء أعضاء القسم: كم عضواً شارك فيه، وكم منهم متصل الآن.
 *
 * «متصل» يعني ختم مشاهدة حُدّث قبل دقيقتين. الختم يُحدَّث في كل دورة تحديث
 * دوري، فالرقم يعكس وجوداً فعلياً لا تخميناً. العتبة دقيقتان لأن أبطأ دورة
 * تحديث مسموحة 30 ثانية، فدقيقتان تمنع ظهور العضو متصلاً وهو خرج للتوّ.
 */
async function chatRoomStats(
  env: Env, roomId: string,
): Promise<{ members: number; online: number }> {
  const since = Date.now() - 120_000
  const [mem, on] = await Promise.all([
    env.XDB.prepare(
      `SELECT COUNT(DISTINCT user_id) c FROM x_chat_messages
       WHERE room_id = ?1 AND deleted = 0`
    ).bind(roomId).first<{ c: number }>(),
    env.XDB.prepare(
      `SELECT COUNT(*) c FROM x_chat_seen
       WHERE room_id = ?1 AND seen_at >= ?2`
    ).bind(roomId, since).first<{ c: number }>(),
  ])
  return { members: Number(mem?.c ?? 0), online: Number(on?.c ?? 0) }
}

/**
 * البثّ التفاضلي: يُرجع الجديد بعد `since` وحده، أو الأحدث صفحةً واحدة.
 *
 * هذا ما يمنع تحميل المحادثة كاملة كل مرة، ويمنع الانهيار عند آلاف الرسائل:
 * الطلب الدوري عادةً يحمل صفراً أو رسالة أو رسالتين، والصفحة الأولى محدودة
 * بـ40، والأقدم تُجلب عند التمرير للأعلى على دفعات.
 */
async function chatPage(
  env: Env, roomId: string, opts: { since?: number; before?: number; limit: number },
): Promise<{ messages: any[]; hasMore: boolean }> {
  const { since = 0, before = 0, limit } = opts
  // الردّ يُجلب في الاستعلام نفسه (LEFT JOIN بسيط): جلب سياق كل ردّ بنداء
  // منفصل يعني عشرات النداءات في صفحة واحدة، وهذا ما يتجنّبه الترقيم أصلاً.
  const cols = `m.id, m.room_id, m.user_id, m.kind, m.body, m.media_key,
       m.media_mime, m.media_size, m.created_at, m.waveform, m.media_seconds,
       m.reply_to, r.body AS reply_to_body, r.kind AS reply_to_kind,
       COALESCE(p.nickname, '') AS reply_to_name`
  const joins = `FROM x_chat_messages m
     LEFT JOIN x_chat_messages r ON r.id = m.reply_to
     LEFT JOIN x_chat_profiles p ON p.user_id = r.user_id`
  let rows: D1Result<any>
  if (since > 0) {
    // رسائل جديدة منذ آخر تحديث — تصاعدي لنعرضها بترتيبها الطبيعي
    rows = await env.XDB.prepare(
      `SELECT ${cols} ${joins}
       WHERE m.room_id = ?1 AND m.deleted = 0 AND m.created_at > ?2
       ORDER BY m.created_at ASC LIMIT ?3`
    ).bind(roomId, since, limit).all<any>()
    return { messages: rows.results ?? [], hasMore: false }
  }
  rows = await env.XDB.prepare(
    `SELECT ${cols} ${joins}
     WHERE m.room_id = ?1 AND m.deleted = 0 ${before > 0 ? 'AND m.created_at < ?3' : ''}
     ORDER BY m.created_at DESC LIMIT ?2`
  ).bind(...(before > 0 ? [roomId, limit, before] : [roomId, limit])).all<any>()
  const list = rows.results ?? []
  // الأحدث أولاً في الاستعلام، ويُعرض تصاعدياً في التطبيق
  return { messages: list.slice().reverse(), hasMore: list.length === limit }
}





// ───────────────────────── الدفع عبر FCM ─────────────────────────

/**
 * الدفع الحقيقي لإشعارات أندرويد.
 *
 * يحتاج حساب خدمة Firebase (سرّ `FCM_SERVICE_ACCOUNT`). بلا هذا السرّ تبقى
 * كل الدوال هنا صامتة: التطبيق يعمل، والإشعارات المحلية تعمل، ولا دفع.
 * هذا مقصود — لا نريد بناءً يفشل لأن سرّاً غير مضبوط في بيئة لم تُهيّأ بعد.
 *
 * المسار: نوقّع JWT بـ RS256 بمفتاح الحساب، نستبدله برمز وصول من Google،
 * ثم نرسل للجهاز عبر FCM HTTP v1. لا نستخدم المفتاح القديم (server key):
 * أوقفت Google الدفع به وأصبح غير موثوق.
 */

interface FcmAccount {
  project_id: string
  client_email: string
  private_key: string
}

let _fcmAccount: FcmAccount | null | undefined
let _fcmToken: { value: string; exp: number } | null = null

function fcmAccount(env: Env): FcmAccount | null {
  if (_fcmAccount !== undefined) return _fcmAccount
  const raw = env.FCM_SERVICE_ACCOUNT
  if (!raw) return (_fcmAccount = null)
  try {
    const j = JSON.parse(raw) as FcmAccount
    if (!j.client_email || !j.private_key) return (_fcmAccount = null)
    // الأسرار تُخزَّن غالباً بأسطر مهرَّبة؛ نعيدها قبل الاستخدام وإلا فشل
    // تحليل المفتاح برسالة غامضة.
    if (!j.private_key.includes('\n')) j.private_key = j.private_key.replace(/\\n/g, '\n')
    if (env.FCM_PROJECT_ID) j.project_id = env.FCM_PROJECT_ID
    return (_fcmAccount = j)
  } catch {
    return (_fcmAccount = null)
  }
}

function b64url(bytes: Uint8Array | string): string {
  const bin = typeof bytes === 'string'
    ? bytes
    : Array.from(bytes, b => String.fromCharCode(b)).join('')
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function pemToPkcs8(pem: string): ArrayBuffer {
  const body = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')
  const bin = atob(body)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out.buffer
}

/** رمز وصول Google، ويُخزَّن حتى انتهائه لتجنّب توقيع JWT لكل إشعار. */
async function fcmAccessToken(account: FcmAccount): Promise<string | null> {
  const now = Math.floor(Date.now() / 1000)
  if (_fcmToken && _fcmToken.exp > now + 60) return _fcmToken.value
  try {
    const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }))
    const claim = b64url(JSON.stringify({
      iss: account.client_email,
      scope: 'https://www.googleapis.com/auth/firebase.messaging',
      aud: 'https://oauth2.googleapis.com/token',
      iat: now,
      exp: now + 3600,
    }))
    const key = await crypto.subtle.importKey(
      'pkcs8', pemToPkcs8(account.private_key),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign'],
    )
    const sig = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(`${header}.${claim}`),
    )
    const jwt = `${header}.${claim}.${b64url(new Uint8Array(sig))}`
    const res = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
    })
    if (!res.ok) return null
    const j = await res.json() as { access_token?: string; expires_in?: number }
    if (!j.access_token) return null
    _fcmToken = { value: j.access_token, exp: now + (j.expires_in ?? 3600) }
    return _fcmToken.value
  } catch {
    return null
  }
}

interface PushPayload {
  title: string
  body: string
  /** حمولة الوجهة كما يفكّها التطبيق: {k:'chat',r:'...'} أو {k:'ad'}. */
  target: { k: string; r?: string }
  /** معرّف لإزالة التكرار عند إعادة المحاولة. */
  collapseKey?: string
}

/**
 * يرسل إشعاراً لرموز أجهزة. يُعيد عدد ما قُبل، ويمسح الرموز الميتة.
 *
 * الرمز الميت (`UNREGISTERED` أو `INVALID_ARGUMENT`) يُحذف فوراً: إبقاؤه
 * يجعل كل إرسال لاحق يدفع ثمناً بلا أمل، ويخفي أن التثبيت زال.
 */
async function fcmSend(
  env: Env, tokens: string[], payload: PushPayload,
): Promise<number> {
  const account = fcmAccount(env)
  if (!account || tokens.length === 0) return 0
  const token = await fcmAccessToken(account)
  if (!token) return 0

  const url = `https://fcm.googleapis.com/v1/projects/${account.project_id}/messages:send`
  let sent = 0
  const dead: string[] = []

  // التزامن المحدود: قسم نشِط قد يحمل مئات الأجهزة، وفتح نداء لكل رمز دفعة
  // واحدة يستهلك حدود الاتصال. عشرات متوازية تكفي بلا انفجار.
  const queue = [...tokens]
  const workers = Array.from({ length: Math.min(10, queue.length) }, async () => {
    for (;;) {
      const t = queue.shift()
      if (!t) return
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${token}`,
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            message: {
              token: t,
              // `data` لا `notification`: نريد التطبيق يبني الإشعار بنفسه
              // فيظهر بنفس القناة والأيقونة والوجهة التي يعرفها.
              data: {
                title: payload.title,
                body: payload.body,
                target: JSON.stringify(payload.target),
              },
              android: {
                priority: 'HIGH',
                ...(payload.collapseKey ? { collapse_key: payload.collapseKey } : {}),
              },
            },
          }),
        })
        if (res.ok) { sent++; continue }
        const j = await res.json().catch(() => null) as
          { error?: { status?: string; details?: Array<{ errorCode?: string }> } } | null
        const status = j?.error?.status ?? ''
        const code = j?.error?.details?.[0]?.errorCode ?? ''
        if (status === 'NOT_FOUND' || status === 'INVALID_ARGUMENT' ||
            code === 'UNREGISTERED' || code === 'INVALID_ARGUMENT') {
          dead.push(t)
        }
      } catch {
        // خطأ شبكة عابر: الرمز سليم، نتركه للمحاولة القادمة.
      }
    }
  })
  await Promise.all(workers)

  if (dead.length > 0) {
    await env.XDB.prepare(
      `DELETE FROM x_push_tokens WHERE token IN (${dead.map(() => '?').join(',')})`
    ).bind(...dead).run().catch(() => {})
  }
  return sent
}

/** يرسل لكل أجهزة مستخدم إلا جهازه الحالي. */
async function pushToUser(
  env: Env, userId: string, payload: PushPayload, exceptToken = '',
): Promise<number> {
  if (!userId) return 0
  const rows = await env.XDB.prepare(
    'SELECT token FROM x_push_tokens WHERE user_id = ?1'
  ).bind(userId).all<{ token: string }>()
  const tokens = (rows.results ?? []).map(r => r.token).filter(t => t && t !== exceptToken)
  return fcmSend(env, tokens, payload)
}

/** يرسل لكل الأجهزة المسجّلة — لإعلان عام. */
async function pushToAll(
  env: Env, payload: PushPayload, exceptToken = '',
): Promise<number> {
  const rows = await env.XDB.prepare('SELECT token FROM x_push_tokens')
    .all<{ token: string }>()
  const tokens = (rows.results ?? []).map(r => r.token).filter(t => t && t !== exceptToken)
  return fcmSend(env, tokens, payload)
}

/** هل الدفع مهيّأ؟ يظهر للتشخيص في رد لوحة المالك. */
function pushEnabled(env: Env): boolean {
  return fcmAccount(env) !== null
}

/**
 * ينبّه أعضاء القسم برسالة جديدة.
 *
 * الشروط مطابقة لما يقرّره التطبيق في جانبه، لأن الخادم هو من يملك القائمة
 * الكاملة للأجهزة: لا إشعار لصاحب الرسالة، ولا لمن كتم الإشعارات.
 *
 * ولا ننتظر النتيجة في مسار الطلب: الإرسال قد يستغرق ثواني مع مئات الأجهزة،
 * وإرسال الرسالة نفسه يجب أن يعود فوراً. النداء يقع عبر `waitUntil` فيتمّ
 * في الخلفية بلا تأخير المستخدم.
 */
async function pushRoomMessage(
  env: Env, roomId: string, authorId: string, authorName: string, preview: string,
): Promise<number> {
  if (!pushEnabled(env)) return 0
  const rows = await env.XDB.prepare(
    `SELECT t.token AS token, COALESCE(p.notify, 1) AS notify
     FROM x_push_tokens t
     LEFT JOIN x_chat_profiles p ON p.user_id = t.user_id
     WHERE t.user_id <> ?1`
  ).bind(authorId).all<{ token: string; notify: number }>()
  const tokens = (rows.results ?? [])
    .filter(r => r.notify !== 0)
    .map(r => r.token)
  if (!tokens.length) return 0
  return fcmSend(env, tokens, {
    title: authorName || 'رسالة جديدة',
    body: preview || 'أرسل مرفقاً',
    target: { k: 'chat', r: roomId },
    // الرسائل المتتابعة في القسم نفسه تُطوى لا تُكدَّس.
    collapseKey: `room_${roomId}`,
  })
}

/**
 * سطر مختصر للرسالة يُعرض في الإشعار.
 *
 * رسالة الوسائط جسدها فارغ غالباً، فتظهر في الإشعار فراغاً بلا معنى. نستبدلها
 * بوصف قصير، ونطابق ما يعرضه التطبيق في جانبه حتى لا يختلف النصّان.
 */
function chatPreview(kind: string, body: string, seconds: number): string {
  const text = (body ?? '').trim()
  if (text) return text.length <= 120 ? text : `${text.slice(0, 120)}…`
  if (kind === 'image') return 'أرسل صورة'
  if (kind === 'video') return 'أرسل مقطع فيديو'
  if (kind === 'audio') return seconds > 0 ? `أرسل رسالة صوتية (${seconds} ث)` : 'أرسل رسالة صوتية'
  return ''
}


/**
 * ترحيل خفيف يُنفَّذ مرة واحدة لكل نسخة من العامل.
 *
 * القاعدة أُنشئت قبل وجود عمود الردّ، و`CREATE TABLE IF NOT EXISTS` لا
 * يضيف أعمدة إلى جدول قائم. نُضيفها هنا بـALTER محميّ: الأخطاء «العمود
 * موجود» أو «الجدول موجود» تُبتلع، وأي خطأ آخر لا يُفشل الطلب.
 *
 * المفتاح نفسه يمنع تكرار التنفيذ: نُخزّن وعداً واحداً على مستوى الوحدة،
 * فكل الطلبات المتزامنة تنتظره بدل أن تتسابق على ALTER.
 */
let chatSchemaReady: Promise<void> | null = null
function ensureChatSchema(env: Env): Promise<void> {
  if (chatSchemaReady) return chatSchemaReady
  chatSchemaReady = (async () => {
    const steps = [
      "ALTER TABLE x_chat_messages ADD COLUMN reply_to TEXT NOT NULL DEFAULT ''",
      `CREATE TABLE IF NOT EXISTS x_chat_uploads (
         id           TEXT PRIMARY KEY,
         room_id      TEXT NOT NULL,
         user_id      TEXT NOT NULL,
         object_key   TEXT NOT NULL,
         r2_upload_id TEXT NOT NULL,
         kind         TEXT NOT NULL DEFAULT 'video',
         mime         TEXT NOT NULL DEFAULT 'video/mp4',
         size_bytes   INTEGER NOT NULL DEFAULT 0,
         seconds      INTEGER NOT NULL DEFAULT 0,
         reply_to     TEXT NOT NULL DEFAULT '',
         text         TEXT NOT NULL DEFAULT '',
         parts_done   INTEGER NOT NULL DEFAULT 0,
         created_at   TEXT NOT NULL
       )`,
      `CREATE INDEX IF NOT EXISTS x_chat_uploads_user
         ON x_chat_uploads (user_id, created_at)`,
    ]
    for (const sql of steps) {
      try {
        await env.XDB.prepare(sql).run()
      } catch {
        // العمود أو الجدول موجود مسبقاً — الحالة الطبيعية بعد أول ترحيل.
      }
    }
  })().catch(() => { chatSchemaReady = null })
  return chatSchemaReady
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url)
    const path = url.pathname

    try {
      // مسارات الدردشة وحدها تحتاج الترحيل؛ ننتظره قبل معالجتها.
      if (path.startsWith('/v1/chat/')) await ensureChatSchema(env)
      if (!['GET', 'POST', 'PUT', 'DELETE'].includes(request.method)) throw new HttpError(405, 'method not allowed')
      if (path === '/health') return json({ ok: true, ts: Date.now() })

      // تنزيل حِزم الإصدارات — عام بلا توقيع ولا جلسة، وبلا فحص حظر.
      //
      // لماذا؟ من يرى شاشة «حدّث التطبيق» قد يكون محجوباً أو جهازه محظوراً،
      // وهو أحوج الناس إلى الرابط. ولأن التنزيل يجري من متصفح لا من التطبيق
      // فلا توقيع فيه أصلاً. الحماية هنا في اسم الملف المسموح وحده: لا مسارات
      // ولا مجلدات، فلا يمكن استخدامه للوصول إلى مفاتيح أخرى في الدلو.
      // ملف واحد لكل معمارية + ملف شامل. اسم الإصدار مقروء من الرابط
      // (`?v=` اختياري) وإلا فالحالي. النسخ القديمة تبقى محمّلة بالاسم
      // الصريح، فلا ينكسر رابط نشره المالك لاحقاً.
      if (path === '/download/PhoneX.apk' || path === '/download') {
        const name = 'PhoneX-v2.0.2.apk'
        const obj = await env.RELEASES.get(name)
        if (!obj) throw new HttpError(404, 'الحزمة غير متوفرة')
        return new Response(obj.body, {
          headers: {
            'Content-Type': 'application/vnd.android.package-archive',
            'Content-Disposition': `attachment; filename="${name}"`,
            'Cache-Control': 'public, max-age=300'
          }
        })
      }

      if (BLOCKED_UA.test(request.headers.get('user-agent') ?? '')) throw new HttpError(403, 'forbidden')
      // مسارات المالك وتسجيل الدخول معفاة من فحص الحظر: بدون ذلك يبقى
      // المالك خارج تطبيقه نهائياً إذا حُظر جهازه أو عنوانه (نقرة خاطئة على
      // زر الحظر، أو حظر تلقائي)، لأنه لا يصل لصفحة إلغاء الحظر أصلاً —
      // فحص الحظر يسبق المصادقة. بقية المسارات محمية كما هي، والوصول إلى
      // /v1/owner/* يظل محكوماً بجلسة owner موقّعة.
      const banExempt = path.startsWith('/v1/owner') || path === '/v1/auth/login'
      if (!banExempt) {
        await assertIpClean(env, request)
        await assertDeviceAllowed(env, request)
        await trackDeviceFarm(env, request)
      }

      // توقيع التطبيق إلزامي لكل /v1/* — السكريبتات الخارجية تموت هنا.
      // تسجيل المفتاح العام معفى: لا يمكن توقيع طلب بمفتاح لم يُسجَّل بعد،
      // وهو الطلب الوحيد الذي يسبق وجود التوقيع. حمايته في حدّ المعدّل
      // وطول المفتاح، لا في التوقيع.
      // روابط بثّ الدروس بالرمز معفاة هنا: المشغّل لا يرسل ترويسات توقيع،
      // والرمز يُفحص داخل معالج البثّ قبل قراءة أي بايت — الإعفاء من
      // البوابة ليس إعفاءً من التحقق.
      if (path.startsWith('/v1/') && path !== '/v1/install/key' &&
          !learnTokenRequest(request)) {
        await verifySignature(env, request)
      }

      // حدّ الانفجار على كل مسارات التطبيق: نافذة ثانية واحدة توقف الحلقات
      // الآلية مهما كانت نافذة الحدّ الأخرى طويلة. مسارات المالك مستثناة
      // لأن رفع الأفدية المقطّعة يرسل أجزاء متتابعة بسرعة مشروعة.
      if (path.startsWith('/v1/') && !path.startsWith('/v1/owner')) {
        // 40/ثانية كان قريباً من تحميل معرض صور على شبكة سريعة (عشرون
        // صورة + استقصاءات في الثانية نفسها). 120 تبقى دون أي استعمال بشري
        // وتمنع الحلقة الآلية التي تفعل آلافاً في الثانية.
        await burstLimit(env, request, 'api', 120)
      }

      const settings = await xSettings(env.XDB)
      // المسارات التي تُخبر التطبيق *لماذا* هو محجوب لا يجوز أن تُحجب، وإلا
      // صار الحجب صامتاً: التطبيق يرى خطأ اتصال لا رسالة المالك، فلا يفهم
      // المستخدم شيئاً ولا يعرف كيف يحدّث. `/v1/bootstrap` هو القناة الوحيدة
      // التي تحمل نصّ القفل ورابط التحديث، فيُستثنى من البوابة.
      //
      // واللوحة مستثناة كذلك كي لا يُقفل المالك خارج لوحته إن رفع الحدّ
      // الأدنى فوق إصدار تطبيقه — وهذا خطأ لا يُصلَح من التطبيق أصلاً.
      const gateExempt = path === '/v1/bootstrap' || path.startsWith('/v1/owner')
      if (settings.appLocked && !gateExempt) {
        throw new HttpError(503, settings.lockMessage || 'التطبيق متوقف مؤقتاً للصيانة')
      }
      // بثّ الدروس بالرمز معفى من بوابة الإصدار: المشغّل لا يرسل ترويسة
      // `x-app-version` أصلاً فكان يُردّ بـ426 — هذا هو «تعذّر التشغيل»
      // الكامل. الرمز نفسه صدر لتطبيق اجتاز البوابة عند جلب الدورات.
      if (!gateExempt && !learnTokenRequest(request)) {
        const gate = versionGate(request, settings)
        if (gate) return gate
      }

      // ---------- عام (موقّع، بدون جلسة) ----------

      if (path === '/v1/bootstrap' && request.method === 'GET') {
        return json({
          ok: true,
          serverTime: Date.now(),
          settings: {
            // المنحة اليومية الواحدة لكل الأدوار.
            dailyFreeQuota: settings.dailyFreeQuota,
            guestFileQuota: settings.guestFileQuota,
            guestCompatQuota: settings.guestCompatQuota,
            compatSearchCost: settings.compatSearchCost,
            schemFilePrice: settings.schemFilePrice,
            dailyGiftAmount: settings.dailyGiftAmount,
            videosHidden: settings.videosHidden,
            videosHiddenMessage: settings.videosHiddenMessage,
            minVersion: settings.minVersion,
            // النسخ الموقوفة تُرسل للتطبيق صراحةً. غيابها هنا كان يجعل
            // «إيقاف إصدار محدد» في اللوحة بلا أثر على الإطلاق: التطبيق
            // يقارن بقائمة فارغة أبداً، فيمرّ الإصدار الموقوف.
            blockedVersions: settings.blockedVersions,
            // نص القفل ونص التحديث: يصلان في نفس الردّ الذي يحمل سبب
            // الحجب، فتظهر رسالة المالك لا رسالة عامة.
            appLocked: settings.appLocked,
            lockMessage: settings.lockMessage,
            telegramLink: settings.telegramLink,
            schematicsLocked: settings.schematicsLocked,
            compatLocked: settings.compatLocked,
            packages: settings.packages,
            privacyPolicy: settings.privacyPolicy,
            // الدردشة تُعلن وجودها مبكراً حتى يعرف التطبيق أي تبويب يعرض.
            chatEnabled: settings.chatEnabled,
            // إعدادات الدردشة تصل للتطبيق لا للوحة فقط: بدونها كان التطبيق
            // يمنع الزائر من الكتابة محلياً ولو سمح المالك له صراحةً.
            chatReadOnly: settings.chatReadOnly,
            chatWriteScope: settings.chatWriteScope,
            chatMediaScope: settings.chatMediaScope,
            guestChatEnabled: settings.chatWriteScope === 'all'
          },
          update: {
            message: settings.updateMessage,
            url: settings.updateUrl,
            imageUrl: settings.updateImageUrl
          },
          announcements: await announcements(env)
        })
      }

      if (path === '/v1/install' && request.method === 'POST') {
        await rateLimit(env, request, 'install', 30, 3600)
        const body = await request.json() as { installId?: string; appVersion?: string }
        const installId = body.installId?.trim()
        if (!installId || installId.length > 80) throw new HttpError(400, 'installId required')
        const now = new Date().toISOString()
        await env.XDB.prepare(
          `INSERT INTO x_installs (install_id, device_id, app_version, first_seen, last_seen, last_ip)
           VALUES (?1, ?2, ?3, ?4, ?4, ?5)
           ON CONFLICT(install_id) DO UPDATE SET last_seen = ?4, app_version = ?3, last_ip = ?5`
        ).bind(installId, deviceOf(request) || null, body.appVersion ?? 'unknown', now, ip(request)).run()

        // مكافأة أول تثبيت: عملات ترحيب تُضاف للمحفظة مرة واحدة لكل جهاز.
        //
        // المفتاح هو بصمة الجهاز (ANDROID_ID عبر x-device-fp) لا التثبيت:
        // مسح البيانات أو إعادة التثبيت يولّد تثبيتاً ومحفظة جديدين لكن
        // البصمة ثابتة، فالصفّ يبقى شاهداً ولا تتكرر المنحة. ووقت الهاتف
        // لا يدخل الحساب أصلاً — القرار والطابع كلاهما بساعة الخادم.
        //
        // بلا بصمة صالحة لا مكافأة: نسخة قديمة بلا x-device-fp تمرّ بلا
        // منح، بدل أن يُمنح على هوية هشّة تعيد إنتاج نفسها كل تشغيل.
        let bonus = 0
        const bonusAmount = Math.max(0, Math.min(1000,
          Math.floor(Number(settings.installBonus) || 0)))
        const bonusFp = fingerprint(request)
        if (bonusAmount > 0 && bonusFp.startsWith('fp:')) {
          const grant = await env.XDB.prepare(
            `INSERT INTO x_install_bonus (fp, install_id, granted_at)
             VALUES (?1, ?2, ?3) ON CONFLICT(fp) DO NOTHING
             RETURNING fp`
          ).bind(bonusFp, installId, now).run()
          if (grant.results.length) {
            // المفتاح الذرّي نجح: هذا الجهاز لم يأخذ مكافأته بعد.
            // الإيداع في محفظة التثبيت الحالية أياً كان مفتاحها.
            const wk = await walletOf(env, request)
            const nowMs = Date.now()
            const credit = await env.XDB.prepare(
              `INSERT INTO x_guest_wallets (device_id, balance, expires_at, created_at, updated_at)
               SELECT ?1, ?2, 0, ?3, ?3 WHERE changes() = 1
               ON CONFLICT(device_id) DO UPDATE SET
                 balance = CASE WHEN expires_at > 0 AND expires_at <= ?4
                   THEN ?2 ELSE balance + ?2 END,
                 expires_at = CASE WHEN expires_at > 0 AND expires_at <= ?4
                   THEN 0 ELSE expires_at END,
                 updated_at = ?3
               RETURNING balance`
            ).bind(wk, bonusAmount, now, nowMs).run()
            if (credit.results.length) {
              bonus = bonusAmount
              await logSecurity(env, request, 'install_bonus',
                `install=${installId.slice(0, 10)} amount=${bonusAmount}`)
            }
          }
        }
        return json({ ok: true, bonus })
      }

      /**
       * تسجيل المفتاح العام للتثبيت — نقطة الدخول الوحيدة قبل وجود توقيع.
       *
       * التطبيق يولّد زوج مفاتيح Ed25519 عند أول تشغيل، يحفظ الخاص في مخزن
       * الجهاز ولا يُخرجه أبداً، ويرسل العام هنا مرة واحدة. من هذه اللحظة
       * يُتحقَّق من كل طلب بتوقيع لا يقدر عليه غيره.
       *
       * الثقة الأولى (TOFU): من يسجّل أولاً باسم تثبيت يملكه. وهذا لا يمنح
       * شيئاً: التسجيل لا يصدر رصيداً ولا صلاحية، والاستحقاق يبقى مشروطاً
       * بجلسته وبكود المالك. ولو سجّل غريب مفتاحه مكان تثبيت قائم، فلن
       * يُقبل مفتاحه أصلاً لأن التسجيل لا يستبدل مفتاحاً قائماً.
       */
      if (path === '/v1/install/key' && request.method === 'POST') {
        await rateLimit(env, request, 'install_key', 30, 3600)
        const b = await request.json().catch(() => ({})) as {
          installId?: string; publicKey?: string; appVersion?: string
        }
        const installId = String(b.installId ?? '').trim()
        const publicKey = String(b.publicKey ?? '').trim().toLowerCase()
        if (!/^[\w-]{8,80}$/.test(installId)) throw new HttpError(400, 'installId غير صالح')
        // مفتاح Ed25519 العام 32 بايت = 64 محرفاً سادس عشرياً بالضبط.
        if (!/^[0-9a-f]{64}$/.test(publicKey)) throw new HttpError(400, 'publicKey غير صالح')
        const now = new Date().toISOString()
        const existing = await env.XDB
          .prepare('SELECT public_key, revoked FROM x_install_keys WHERE install_id = ?1')
          .bind(installId).first<{ public_key: string; revoked: number }>()
        if (existing) {
          // المفتاح نفسه مسجّل من قبل: نداء متكرّر بعد إعادة تشغيل التطبيق،
          // فيُقبل بلا تغيير. مفتاح مختلف يعني إما تثبيتاً أُعيد ضبطه أو
          // محاولة انتحال — كلاهما لا يُحلّ هنا، ولا يُمنح مفتاح جديد بصمت.
          if (existing.public_key === publicKey && !existing.revoked) {
            await env.XDB.prepare(
              'UPDATE x_install_keys SET last_seen = ?1, device_id = ?2 WHERE install_id = ?3'
            ).bind(now, deviceOf(request) || '', installId).run()
            return json({ ok: true, reused: true })
          }
          await logSecurity(env, request, 'install_key_conflict', `install=${installId}`)
          throw new HttpError(409, 'مفتاح هذا التثبيت مسجَّل بالفعل')
        }
        await env.XDB.prepare(
          `INSERT INTO x_install_keys (install_id, public_key, device_id, app_version,
             last_ts, revoked, first_seen, last_seen)
           VALUES (?1, ?2, ?3, ?4, 0, 0, ?5, ?5)`
        ).bind(installId, publicKey, deviceOf(request) || '',
               String(b.appVersion ?? '').slice(0, 20), now).run()
        return json({ ok: true, enrolled: true })
      }

      // ---------- المصادقة ----------

      if (path === '/v1/auth/guest' && request.method === 'POST') {
        // 60 بدل 10: إنشاء الجلسة يحدث في كل فتح، والحدّ الضيّق كان يرفض
        // المستخدم في أول تشغيل. المفتاح صار الجهاز فلا يضر أحداً بغيره.
        await rateLimit(env, request, 'guest', 60, 3600)
        const installId = verifiedInstallOf(request)
        if (!installId) throw new HttpError(403, 'طلب غير موثّق')
        const dev = deviceOf(request)
        // الهوية من التثبيت الموثّق لا من الترويسة. `guest_<deviceId>` كان
        // يعني أن من وضع معرّف جهاز غيره حصل على هوية ذلك الجهاز في الدردشة
        // (يقرأ رسائله ويحذفها). الترويسة تبقى للعرض فقط.
        const token = await signJwt(
          { sub: `guest_${installId}`, role: 'guest', inst: installId, dev },
          env.X_JWT_SECRET, 7 * DAY)
        return json({ token, user: { id: `guest_${installId}`, role: 'guest' } })
      }

      if (path === '/v1/auth/register' && request.method === 'POST') {
        await rateLimit(env, request, 'register', 8, 3600)
        const body = await request.json() as { username?: string; password?: string; displayName?: string; note?: string }
        const username = body.username?.trim() ?? ''
        const password = body.password ?? ''
        if (!/^[\w.\-@]{3,60}$/.test(username)) throw new HttpError(400, 'اسم مستخدم غير صالح')
        if (password.length < 6) throw new HttpError(400, 'كلمة المرور قصيرة')
        if (await xUserByName(env.XDB, username)) throw new HttpError(409, 'اسم المستخدم مستخدم')
        const id = `u_${uid()}`
        await env.XDB.batch([
          env.XDB.prepare(
            `INSERT INTO x_users (id, username, display_name, password_hash, role, active, device_id, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, 'user', 0, ?5, 0, ?6)`
          ).bind(id, username, body.displayName?.trim() ?? '', await hashPassword(password), deviceOf(request) || null, new Date().toISOString()),
          env.XDB.prepare(
            `INSERT INTO x_requests (id, username, note, device_id, status, created_at) VALUES (?1, ?2, ?3, ?4, 'pending', ?5)`
          ).bind(`r_${uid()}`, username, body.note?.trim() ?? '', deviceOf(request) || null, new Date().toISOString())
        ])
        return json({ ok: true, pending: true, telegram: settings.telegramLink })
      }

      if (path === '/v1/auth/login' && request.method === 'POST') {
        await rateLimit(env, request, 'login', 10, 600)
        const body = await request.json() as { username?: string; password?: string }
        const user = await xUserByName(env.XDB, body.username?.trim() ?? '')
        if (!user || !(await verifyPassword(body.password ?? '', (user as any).password_hash ?? ''))) {
          await noteAbuse(env, request, 'bad_login', 'low')
          await logSecurity(env, request, 'bad_login', `user=${body.username ?? ''}`)
          throw new HttpError(401, 'بيانات الدخول غير صحيحة')
        }
        if (!user.active) throw new HttpError(403, 'الحساب بانتظار تفعيل المالك')
        const token = await signJwt({ sub: user.id, role: user.role }, env.X_JWT_SECRET, 30 * DAY)
        return json({
          token,
          user: { id: user.id, username: user.username, displayName: user.display_name, role: user.role }
        })
      }

      // إنشاء حساب المالك لأول مرة — محمي بمفتاح سري + يعمل مرة واحدة فقط
      if (path === '/v1/owner/bootstrap' && request.method === 'POST') {
        const key = request.headers.get('x-owner-key')?.trim()
        if (!env.X_OWNER_KEY || key !== env.X_OWNER_KEY) {
          await noteAbuse(env, request, 'bad_owner_key')
          await logSecurity(env, request, 'bad_owner_key')
          throw new HttpError(403, 'forbidden')
        }
        const existing = await env.XDB.prepare("SELECT id FROM x_users WHERE role = 'owner' LIMIT 1").first()
        if (existing) throw new HttpError(409, 'owner exists')
        const body = await request.json() as { username?: string; password?: string }
        const username = body.username?.trim() ?? 'owner'
        if ((body.password ?? '').length < 8) throw new HttpError(400, 'password too short')
        await env.XDB.prepare(
          `INSERT INTO x_users (id, username, display_name, password_hash, role, active, device_id, expires_at, created_at)
           VALUES (?1, ?2, 'المالك', ?3, 'owner', 1, NULL, 0, ?4)`
        ).bind(`owner_${uid()}`, username, await hashPassword(body.password!), new Date().toISOString()).run()
        return json({ ok: true })
      }

      // ---------- دخول المالك: مسار معزول بسرّ مستقل ----------
      // لا يمرّ على authenticate العادي: جلسته تُوقَّع بمفتاح مختلف وتحمل
      // typ=owner، فلا يمكن تحويل جلسة مستخدم عادي إلى جلسة مالك.
      if (path === '/v1/owner/login' && request.method === 'POST') {
        await ownerLoginGuard(env)
        // الهوية من التوقيع لا من الترويسة: `x-device-id` يملك العميل
        // تغييره، فلو بُني السقف عليه لكان كل محاولة دخول «جهازاً جديداً»
        // بتغيير حرف واحد — فيسقط حدّ الأجهزة كلياً.
        const installId = verifiedInstallOf(request)
        if (!installId) throw new HttpError(403, 'طلب غير موثّق')
        const dev = deviceOf(request)
        // فحص السقف قبل كلمة المرور: التثبيت الزائد يُرفض بلا كشف أي شيء عن
        // صحة البيانات، فلا يتحول الطلب إلى مِجَسّ لكلمة المرور.
        const known = await ownerDevices(env)
        const isNew = !known.includes(installId)
        if (isNew && known.length >= MAX_OWNER_DEVICES) {
          await logSecurity(env, request, 'owner_device_limit',
            `install=${installId.slice(0, 10)} agents=${known.length}`)
          throw new HttpError(403,
            `بلغت حدّ الأجهزة المسموح بها (${MAX_OWNER_DEVICES}) — أفرج عن جهاز من اللوحة ثم أعد المحاولة`)
        }
        const body = await request.json() as { username?: string; password?: string }
        const user = await xUserByName(env.XDB, body.username?.trim() ?? '')
        if (!user || user.role !== 'owner' ||
            !(await verifyPassword(body.password ?? '', (user as any).password_hash ?? ''))) {
          await noteOwnerLoginFail(env, request)
          // نفس الرسالة للحالات الثلاث: لا نكشف وجود الحساب ولا دوره.
          throw new HttpError(401, 'بيانات الدخول غير صحيحة')
        }
        await clearOwnerLoginFails(env)
        await logSecurity(env, request, 'owner_login_ok', `uid=${user.id}`)
        const token = await signOwnerJwt(env, { sub: user.id, role: 'owner' }, 12 * 3600)
        // الهاتف الجديد يُسجَّل صريحاً في السجل: دخول من جهاز لم يُرَ قبل
        // ليس حدثاً صامتاً، ولو كانت كلمة المرور صحيحة.
        if (isNew) {
          await registerOwnerDevice(env, installId, dev)
          await logSecurity(env, request, 'owner_device_new', `install=${installId.slice(0, 10)}`)
        }
        // وسم الجهاز صريحاً: هو ما يمنح المالك استحقاق دوراته، لا وجود رمز
        // اللوحة في الطلب. الجلسة قد تنتهي أو تُسحب، والوسم يبقى.
        await markOwnerDevice(env, installId, dev)
        return json({
          ok: true,
          token,
          expiresIn: 12 * 3600,
          user: { id: user.id, username: user.username, role: 'owner' }
        }, 200, { 'cache-control': 'no-store' })
      }

      // ---------- كل المسارات التالية تتطلب جلسة (زائر أو مستخدم) ----------

      // طلبات البثّ بالرمز لا تحمل جلسة: المشغّل يستدعي الرابط كما وصله.
      // استحقاقها يأتي من الرمز الموقّع الذي يُفحص في المعالج — لذلك تُمنح
      // مصادقة اصطناعية ضيف لا تملك شيئاً سوى المسار نفسه.
      const auth = learnTokenRequest(request)
        ? { caller: { uid: '', role: 'guest' }, user: null }
        : await authenticate(env, request)
      const caller = auth.caller

      // ---------- بيانات التوافقات (قراءة من المرآة فقط) ----------

      if (path === '/v1/data/brands' && request.method === 'GET') {
        await rateLimit(env, request, 'list', 300, 600)
        if (caller.role === 'guest' && settings.compatLocked) {
          throw new HttpError(403, 'التوافقات للمشتركين فقط — تواصل مع المالك')
        }
        // `id` بعد الانتشار: حقل `id` الرقمي داخل data كان يطمس مفتاح
        // الوثيقة (b_brand_123) فيصل العميل «328» لا يطابقه أي صفّ عند
        // التحرير — فيردّ الخادم «الصفّ غير موجود». المفتاح مرجع الردّ.
        const brands = (await mirrorCollection(env.MIRROR, 'brands')).map(d => ({ ...d.fields, id: d.id }))
        // شركات فرعية افتراضية (Redmi/POCO/Oppo/Honor/iQOO) — قراءة فقط من ملفات الشركات الأم
        const files = new Set(brands.map(b => (b as any).file))
        for (const vb of VIRTUAL_SUB_BRANDS) {
          if (files.has(vb.file)) {
            brands.push({
              id: `v_${vb.key}`, name: vb.name, file: vb.file,
              imageUrl: '', records: 0, models: 0, virtual: true, keyword: vb.key
            } as any)
          }
        }
        return json({ brands })
      }

      // دخول شركة: هنا يقع الخصم الوحيد. ينفصل عن البحث كي يدفع المستخدم
      // مرة واحدة عند فتح الشركة ويُعرض له رصيده قبل أن يكتب أي حرف.
      if (path === '/v1/data/compat/open' && request.method === 'POST') {
        const body = await request.json() as { brand?: string }
        const brandRef = String(body.brand ?? '').trim().slice(0, 80)
        const fp = await walletOf(env, request)
        const r = await ensureCompatOpen(env, ctx, request, caller, settings, fp, brandRef || 'all')
        return json({
          ok: true,
          charged: r.charged, source: r.source,
          remaining: r.freeLeft, balance: r.balance
        }, 200, { 'cache-control': 'no-store' })
      }

      // بحث التوافقات — بعد دخول الشركة، بلا خصم إضافي.
      // POST لا GET: البحث فعل مكلّف لا يجوز أن يُخزَّن في الكاش أو يُستدعى
      // تلقائياً من متصفح/زاحف، ولا يظهر نصه في سجلات الوسطاء.
      if (path === '/v1/data/compat/search' && request.method === 'POST') {
        await Promise.all([
          rateLimit(env, request, 'compatsearch', 240, 600),
          rateLimit(env, request, 'compatsearchhour', 120, 3600),
          burstLimit(env, request, 'compatsearch', 10)
        ])
        if (caller.role === 'guest' && settings.compatLocked) {
          throw new HttpError(403, 'التوافقات للمشتركين فقط — تواصل مع المالك')
        }
        const body = await request.json() as {
          q?: string; brand?: string; type?: string; limit?: number
        }
        // حدود صارمة: نص طويل أو نوع غير معروف يزيد كلفة LIKE بلا فائدة
        const q = String(body.q ?? '').trim().slice(0, 64).toLowerCase()
        let brandRef = String(body.brand ?? '').trim().slice(0, 80)
        const type = String(body.type ?? '').trim().slice(0, 24).toUpperCase()

        let brandFile = brandRef || undefined
        let keyword: string | undefined
        if (brandRef.startsWith('v_')) {
          const vb = VIRTUAL_SUB_BRANDS.find(v => `v_${v.key}` === brandRef)
          brandFile = vb?.file
          keyword = vb?.key
        }
        // النوع يُفحص بعد معرفة أنواع الشركة: نوع أضافه المالك لهذه الشركة
        // صار نوعاً صحيحاً، ورفضه هنا كان يجعل النوع الذي يعرضه التطبيق
        // غير قابل للبحث — أي ميزة تعطّل نفسها.
        const types = brandFile
          ? await cached(env, `ctypes:${brandFile}`, 3600, () => compatTypesOf(env.MIRROR, brandFile!))
          : [...COMPAT_TYPES]
        // الأنواع التي أضافها المالك تُعرض للجميع أيضاً، وإلا اختار المستخدم
        // نوعاً لا يمكنه البحث فيه أصلاً.
        const ownerTypes = brandFile ? await compatOwnerTypes(env, brandFile) : []
        const allTypes = [...types, ...ownerTypes.filter(t => !types.includes(t))]
        // نوع غير معروف لا يطابق شيئاً — نرفضه بدل تمريره للاستعلام
        if (type && !allTypes.includes(type)) {
          throw new HttpError(400, 'نوع قطعة غير معروف')
        }

        // لا خصم على استعلام فارغ: هو استعراض لأنواع الشركة لا سحب بيانات.
        if (!q) {
          return json({ records: [], types: allTypes, charged: false, remaining: -1 },
            200, { 'cache-control': 'no-store' })
        }

        // الخصم عند دخول الشركة أول مرة في اليوم — لا مع كل نص.
        const fp = await walletOf(env, request)
        const r = await ensureCompatOpen(
          env, ctx, request, caller, settings, fp, brandRef || 'all')

        const raw = await mirrorSearchCompat(env.MIRROR, {
          query: q, brandFile, keyword,
          type: type || undefined,
          limit: Math.max(1, Math.min(Number(body.limit) || 60, 120))
        })
        // تعديلات المالك وصفوفه الجديدة تُدمج هنا وإلا ظلّت مرئية في اللوحة
        // وحدها ولن يراها مستخدم البتة. الدمج قبل فحص السحب كي يُحسب ما
        // سُلّم فعلاً لا ما وُجد في المرآة.
        const tokens = q.split(/\s+/).filter(Boolean).slice(0, 4)
        const results = await mergeCompatEdits(
          env, brandFile, raw, tokens, keyword, type || undefined, 120)
        // سحب قاعدة التوافقات: من يبحث بعبارات مختلفة كثيرة في نافذة واحدة
        // يريد بناء نسخة كاملة، لا أن يجد قطعة. الإعفاء للمالك وحده.
        if (caller.role !== 'owner') {
          await detectSweep(env, request, 'compatq', `${brandRef}|${q}`, 120)
        }
        return json({
          // مفتاح الوثيقة آخراً: `id` الرقمي داخل data يطمس مفتاح الصفّ
          // فيفشل تعديله بـ«غير موجود». الترتيب هنا هو الذي يحدد الفائز.
          records: results.map(d => ({ ...d.fields, id: d.id })),
          types: allTypes, charged: r.charged, source: r.source,
          remaining: r.freeLeft,
          balance: r.balance
        }, 200, {
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff'
        })
      }

      // نفس بحث npm التوافقات لكن بـ GET — يُستعمل للتشخيص وللإصدارات
      // القديمة من التطبيق. يخضع لنفس الخصم تماماً.
      //
      // استعلام فارغ مرفوض: كان يسمح بسحب سجلات شركة كاملة (حتى 500 سجل)
      // بصفر بطاقات، فيكفي المهاجم أن يمرّ على كل الشركات ليحصل على كل
      // التوافقات مجاناً — أي أن نظام العملات كان بلا معنى.
      if (path === '/v1/data/compatibility' && request.method === 'GET') {
        await rateLimit(env, request, 'compat', 60, 600)
        if (caller.role === 'guest' && settings.compatLocked) {
          throw new HttpError(403, 'التوافقات للمشتركين فقط — تواصل مع المالك')
        }
        const q = url.searchParams.get('q')?.trim().slice(0, 64).toLowerCase() ?? ''
        if (!q) {
          throw new HttpError(400, 'نص البحث مطلوب — استخدم /v1/data/compat/search')
        }
        let brandRef = url.searchParams.get('brand')?.trim() ?? ''
        const type = (url.searchParams.get('type')?.trim() ?? '').toUpperCase()
        let brandFile = brandRef || undefined
        let keyword: string | undefined
        if (brandRef.startsWith('v_')) {
          const vb = VIRTUAL_SUB_BRANDS.find(v => `v_${v.key}` === brandRef)
          brandFile = vb?.file
          keyword = vb?.key
        }
        // نوع أضافه المالك يُقبل هنا أيضاً، وإلا صار النوع الذي يعرضه التطبيق
        // غير قابل للبحث في الإصدارات التي تستعمل هذا المسار.
        const ownerTypes = brandFile ? await compatOwnerTypes(env, brandFile) : []
        if (type && !COMPAT_TYPES.includes(type) && !ownerTypes.includes(type)) {
          throw new HttpError(400, 'نوع قطعة غير معروف')
        }
        const fp = await walletOf(env, request)
        const r = await ensureCompatOpen(
          env, ctx, request, caller, settings, fp, brandRef || 'all')
        const raw = await mirrorSearchCompat(env.MIRROR, {
          query: q, brandFile, keyword,
          type: type || undefined,
          limit: Math.min(Number(url.searchParams.get('limit')) || 60, 120)
        })
        const tokens = q.split(/\s+/).filter(Boolean).slice(0, 4)
        const results = await mergeCompatEdits(
          env, brandFile, raw, tokens, keyword, type || undefined, 120)
        return json({
          records: results.map(d => ({ ...d.fields, id: d.id })),
          charged: r.charged, source: r.source,
          remaining: r.freeLeft,
          balance: r.balance
        }, 200, {
          'cache-control': 'no-store',
          'x-quota-remaining': String(r.freeLeft)
        })
      }

      if (path === '/v1/me' && request.method === 'GET') {
        const fp = await walletOf(env, request)
        const freeUsed = 0
        const freeLimit = 0
        const wallet = caller.role === 'guest'
          ? await env.XDB.prepare(
              'SELECT balance, expires_at FROM x_guest_wallets WHERE device_id = ?1'
            ).bind(fp).first<{ balance: number; expires_at: number }>()
          : null
        // رصيد واحد للجميع: بطاقات المشترك ومحفظة الزائر في نفس العدّاد،
        // والمنحة اليومية تُضاف إليه في العرض كما تُخصم منه فعلاً.
        const coins = caller.role === 'user'
          ? auth.user?.quota_balance ?? 0
          : caller.role === 'guest'
            ? wallet?.balance ?? 0
            : 0
        const expiresAt = caller.role === 'user'
          ? auth.user?.quota_expires_at ?? 0
          : wallet?.expires_at ?? 0
        const freeLeft = Math.max(0, freeLimit - freeUsed)
        // حالة هديّة اليوم محسوبة على الخادم لا على التطبيق: التطبيق كان
        // يخمّنها من ردّ 409، فمن أعاد تشغيل التطبيق بعد الاستلام كان يرى
        // الزر متاحاً (الخادم يرد 409 عند الضغط). الاستعلام هنا يجعل الشكل
        // صادقاً من أول تحميل، ومنه أيضاً نعرف متى تُفتح هديّة الغد.
        const giftAmount = Math.max(0, Math.min(1000,
          Math.floor(Number(settings.dailyFreeQuota) || 0)))
        // لحظة الفتح تُقرأ من صفّ المحفظة. بلا هذا كان العدّاد يشير إلى منتصف
        // الليل بينما الاستلام الفعلي بعد 24 ساعة من الاستلام — فرق يصل إلى
        // 24 ساعة بين ما يعرضه العدّاد وما يقبله الخادم.
        // حالة الهدية مفتاحها المحفظة وبصمة الجهاز معاً: تثبيت جديد على
        // نفس الجهاز يجب أن يرى «مستلمة» لا زراً متاحاً — وإلا ظهر الزر
        // ثم ردّ الخادم 409، وهو شكل الخلل الذي شُكي منه.
        const fpKey = fingerprint(request)
        const giftRow = giftAmount > 0
          ? await env.XDB.prepare(
              `SELECT last_at, next_at FROM x_gift_claims
               WHERE wallet IN (?1, ?2) ORDER BY next_at DESC LIMIT 1`
            ).bind(fp, fpKey.startsWith('fp:') ? fpKey : fp)
              .first<{ last_at: number; next_at: number }>()
          : null
        // قاعدة لم تُحدَّث بعد لا تحمل الصفّ: نرجع لفحص اليوم التقويمي كي لا
        // يظهر الزر متاحاً ثم يردّ الخادم 409.
        const nextAt = giftRow
          ? Math.max(Number(giftRow.next_at), Number(giftRow.last_at) + DAY * 1000)
          : 0
        const giftTaken = giftAmount > 0 && nextAt > Date.now()
        return json({
          user: {
            id: caller.uid, role: caller.role,
            username: auth.user?.username ?? null,
            displayName: auth.user?.display_name ?? ''
          },
          // العدّاد الموحّد — مصدر واحد للشريط الأعلى في التطبيق.
          wallet: {
            freeLimit, freeUsed, freeLeft,
            coins, expiresAt,
            totalLeft: caller.role === 'owner' ? -1 : freeLeft + coins,
            cost: Math.max(1, Math.floor(Number(settings.compatSearchCost) || 1))
          },
          // حقول قديمة تبقى للنسخ السابقة من التطبيق، بنفس أرقام العدّاد
          // الموحّد كي لا ترى رقماً يخالف ما يُخصم.
          quota: { used: freeUsed, limit: freeLimit },
          compatQuota: caller.role === 'owner'
            ? null
            : {
                used: freeUsed,
                limit: freeLimit,
                cost: Math.max(1, Math.floor(Number(settings.compatSearchCost) || 1))
              },
          cards: caller.role === 'owner'
            ? null
            : { balance: coins, expiresAt },
          // الهديّة: المبلغ المعتمد، وهل استُلمت اليوم، ومتى تُفتح التالية.
          // المالك يُستثنى لأن رصيده مفتوح أصلاً ولا معنى للهديّة عنده.
          gift: caller.role === 'owner'
            ? { amount: 0, claimed: true, nextAt: 0 }
            : { amount: giftAmount, claimed: giftTaken, nextAt }
        })
      }

      if (path === '/v1/schem/brands' && request.method === 'GET') {
        await rateLimit(env, request, 'list', 300, 600)
        if (caller.role === 'guest' && settings.schematicsLocked) {
          throw new HttpError(403, 'المخططات للمشتركين فقط — تواصل مع المالك')
        }
        const [catalog, local] = await Promise.all([readCatalogBrands(env), listLocalBrands(env)])
        const merged = new Map<string, CatalogBrand>()
        for (const b of catalog) merged.set(b.name.toLowerCase(), b)
        for (const b of local) merged.set(b.name.toLowerCase(), b)
        return json({ brands: [...merged.values()].sort((a, b) => a.name.localeCompare(b.name)) })
      }

      const modelsMatch = path.match(/^\/v1\/schem\/brands\/(.+)\/models$/)
      if (modelsMatch && request.method === 'GET') {
        await rateLimit(env, request, 'list', 300, 600)
        if (caller.role === 'guest' && settings.schematicsLocked) {
          throw new HttpError(403, 'المخططات للمشتركين فقط — تواصل مع المالك')
        }
        const brandId = decodeURIComponent(modelsMatch[1])
        const q = url.searchParams.get('q')?.trim().toLowerCase() ?? ''
        const models = brandId.startsWith(LOCAL_PREFIX)
          ? await listLocalModels(env, brandId)
          : (await readBrandCatalog(env, brandId))?.models ?? []
        return json({
          models: models
            .filter(m => !q || m.name.toLowerCase().includes(q))
        })
      }

      const filesMatch = path.match(/^\/v1\/schem\/folders\/(.+)\/files$/)
      if (filesMatch && request.method === 'GET') {
        await rateLimit(env, request, 'list', 300, 600)
        const folderId = decodeURIComponent(filesMatch[1])
        let files: CatalogEntry[]
        if (folderId.startsWith(LOCAL_PREFIX)) {
          files = await listLocalFiles(env, folderId)
        } else {
          const segs = folderId.startsWith('r2:') ? folderId.slice(3).split('/') : []
          const catalog = segs.length >= 3 ? await readBrandCatalog(env, `r2:${segs[0]}`) : null
          files = catalog?.folders?.[folderId] ?? []
        }
        return json({ files })
      }

      const fileMatch = path.match(/^\/v1\/file\/(.+)$/)
      if (fileMatch && request.method === 'GET') {
        const fileId = decodeURIComponent(fileMatch[1])
        await Promise.all([
          rateLimit(env, request, 'files', 200, 600),
          rateLimit(env, request, 'fileshour', 120, 3600),
          burstLimit(env, request, 'files', 12)
        ])
        const r2Key = fileId.startsWith(LOCAL_PREFIX)
          ? LOCAL_R2 + fileId.slice(LOCAL_PREFIX.length)
          : `schem/${fileId}`

        // لا تُستهلك الحصة إلا إذا كان الملف موجوداً فعلاً
        const headObj = await env.SCHEMATICS.head(r2Key)
        if (!headObj) throw new HttpError(404, 'file not found')
        // السحب المنهجي: من يدور على معرّفات ملفات كثيرة في نافذة واحدة
        // يحاول بناء مكتبة كاملة. عدّ المعرّفات المختلفة يكشفه ولو كان
        // بطيئاً تحت حدّ المعدّل، بينما إعادة فتح الملف نفسه لا تُحتسب.
        if (caller.role !== 'owner') await detectSweep(env, request, 'files', r2Key, 40)
        const fp = await walletOf(env, request)
        // إعادة فتح نفس الملف في اليوم نفسه لا تُخصم مرتين: المستخدم يغلق
        // المخطط ليعود إليه بعد دقيقة، والخصم في كل مرة كان يستنزف رصيده على
        // ملف واحد. لا يُمنع فتح ملفات أخرى — كل ملف جديد يُخصم مرة.
        const remaining = caller.role === 'owner'
          ? -1
          : await consumeFileOnce(env, ctx, request, caller, settings, fp, r2Key)

        // لا كاش حافة بعد الآن: كان الكاش يُخزّن النص المشفّر ثابتاً لكل
        // (ملف+إصدار). مع الخدمة المباشرة صار الكاش يخزّن الملف نفسه، وهذا
        // يقصّر عمر الكاش ويرفع خطر بقاء نسخة بعد تغيّر الصلاحية — فالكاش
        // يُترك للشبكة (`no-store` يمنع الوسائط من تخزينه).

        const object = await env.SCHEMATICS.get(r2Key)
        if (!object?.body) throw new HttpError(404, 'file not found')

        // يُخدَم الملف كما هو فوق TLS — لا تشفير على مستوى التطبيق.
        //
        // كان يُشفَّر AES-CTR بمفتاح مضمَّن في الحزمة (`FileKey`)، ثم يفكّه
        // التطبيق. هذا لم يكن يحمي شيئاً: المفتاح نفسه كان يُستخرج من الـAPK
        // بأمر واحد، فمن وصل إلى الملف وصل إلى مفتاحه. والأسوأ أنه أوهم
        // بأن هناك حماية بينما الأصل هو قناة TLS والتحقق من الجلسة والحصة.
        // إزالة الطبقة تُبقي الحماية الحقيقية وتُزيل سرّاً مضمّناً من الحزمة.
        const headers = new Headers()
        headers.set('content-type', headObj.httpMetadata?.contentType ?? 'application/octet-stream')
        headers.set('x-orig-type', headObj.httpMetadata?.contentType ?? 'application/octet-stream')
        headers.set('x-orig-size', String(headObj.size))
        headers.set('etag', headObj.etag)
        headers.set('cache-control', 'no-store')
        headers.set('x-quota-remaining', String(remaining === Number.MAX_SAFE_INTEGER ? -1 : remaining))
        headers.set('x-cache', 'MISS')

        const response = new Response(object.body, { status: 200, headers })
        return response
      }

      // ---------- الدردشة المجتمعية ----------

      // المستخدم الحالي إن كان مسجّلاً (الزائر بلا صف في x_users).
      const chatUser = auth.user

      // حالة الدردشة: الأقسام، السمات، القيود على المستخدم الحالي.
      // متاحة لكل من يحمل جلسة صالحة (زائر أو مسجّل أو مشترك).
      if (path === '/v1/chat/state' && request.method === 'GET') {
        // حدّ خاص بالدردشة لا يشارك حدّ تصفّح الشركات.
        //
        // كان الاثنان في دلو `list` نفسه. والدردشة تستدعي حالة القسم دورياً
        // (كل ثوانٍ في الشاشة المفتوحة، وكل 20 ثانية في الغلاف للإشعارات)،
        // فاستهلكت الدلو وحدها في دقائق — ثم يفتح المستخدم قائمة شركات
        // فيُرفض بـ429 وهو لم يُكثر شيئاً. العلة كانت في تقاسم الدلو، لا في
        // سرعة أحد.
        // 4 ثوان بين الدورت = 900 طلب في النافذة، فسقف 1200 كان على حدّ
        // الاستعمال الطبيعي — أي شبكة تتقطّع فتعيد الطلب تبلغه. 3000 تعني
        // ثلاثة أضعاف الاستعمال البشري، وتبقى بعيدة جداً عن الأتمتة.
        await rateLimit(env, request, 'chatstate', 3000, 600)
        const meId = chatUser?.id ?? `guest:${caller.uid}`
        const mine = await env.XDB.prepare(
          'SELECT nickname, avatar_key, notify FROM x_chat_profiles WHERE user_id = ?1'
        ).bind(meId).first<{ nickname: string; avatar_key: string; notify: number }>()
        // الزوار بلا حساب لا يمكن كتمهم بحساب: معرّفهم مرتبط بالجهاز وحده.
        const rest = chatUser
          ? await chatRestriction(env, chatUser.id, '')
          : { muted: false, kicked: false, reason: '', until: 0 }
        const write = chatWriteAllowed(settings, caller, chatUser)
        const media = chatMediaAllowed(settings, caller, chatUser)
        return json({
          enabled: settings.chatEnabled,
          readOnly: settings.chatReadOnly,
          theme: settings.chatTheme,
          welcome: settings.chatWelcome,
          maxLength: settings.chatMaxLength,
          imagesEnabled: settings.chatImagesEnabled,
          writeScope: settings.chatWriteScope,
          mediaScope: settings.chatMediaScope,
          maxMediaMb: settings.chatMaxMediaMb,
          mediaSeconds: settings.chatMediaSeconds,
          pollMs: settings.chatPollMs,
          rooms: settings.chatRooms,
          canWrite: write.ok,
          writeBlockedReason: write.ok ? '' : write.reason,
          canSendMedia: media.ok,
          mediaBlockedReason: media.ok ? '' : media.reason,
          isSubscriber: isSubscriber(chatUser),
          me: {
            id: meId,
            nickname: mine?.nickname ?? '',
            avatarUrl: mine?.avatar_key ? `/v1/media/${mine.avatar_key}` : '',
            notify: mine?.notify !== 0,
            role: caller.role,
          },
          restriction: rest,
        })
      }

      /**
       * الرسائل — بثلاثة أنماط:
       *   since  : الجديد بعد ختم زمني (التحديث الدوري) — عادةً صفر أو رسالة.
       *   before : دفعة أقدم عند التمرير للأعلى.
       *   بلا شيء: أحدث صفحة عند أول فتح.
       * لا تُحمَّل المحادثة كاملة في أي حال.
       */
      if (path === '/v1/chat/messages' && request.method === 'GET') {
        await rateLimit(env, request, 'chatread', 3000, 600)
        if (!settings.chatEnabled) throw new HttpError(403, 'الدردشة موقوفة حالياً')
        const roomId = url.searchParams.get('room') ?? ''
        const room = settings.chatRooms.find(r => r.id === roomId)
        if (!room) throw new HttpError(404, 'القسم غير موجود')
        const since = Number(url.searchParams.get('since')) || 0
        const before = Number(url.searchParams.get('before')) || 0
        // حدّ الدفعة: 60 كافٍ لتمرير مريح، وأكثر منه يثقل الرد على الجوال.
        const limit = Math.max(1, Math.min(60, Number(url.searchParams.get('limit')) || 40))

        const page = await chatPage(env, roomId, { since, before, limit })
        const list = page.messages
        const meId = chatUser?.id ?? `guest:${caller.uid}`
        const profiles = await chatProfiles(env.XDB, list.map(m => m.user_id))
        // صور المشاهدين: تُحسب للرسائل التي كتبها غيري فقط، وفي نمط
        // التحديث الدوري للرسائل الجديدة وحدها.
        const others = list.filter(m => m.user_id !== meId).map(m => m.created_at)
        const seers = await chatSeers(env, roomId, others, meId)
        // إحصاء الأعضاء في نمط الفتح فقط: عدّاد لا يتغيّر كل أربع ثوانٍ،
        // وحسابه في كل دورة تحديث دوري هدر بلا فائدة.
        const stats = since > 0
          ? null
          : await chatRoomStats(env, roomId)
        return json({
          room: room.id,
          messages: list.map(m => ({
            ...chatMessageJson(m, profiles.get(m.user_id), meId),
            seenBy: seers.get(m.created_at) ?? [],
          })),
          hasMore: page.hasMore,
          members: stats?.members ?? null,
          online: stats?.online ?? null,
        })
      }

      /**
       * حذف رسالة — لصاحبها فقط، وللمالك على أي رسالة.
       *
       * الحذف نصفي (deleted = 1) لا محو للصف: يحفظ سجل الإشراف ويحول دون
       * أن يعيد الطلبُ الدوري رسالةً حُذفت لأن اتصالاً قديماً ما زال يراقب.
       * ولا يُحذف ملف الوسيط من R2: يفعل ذلك مهمة تنظيف مستقلة، وحذفه هنا
       * يُبقي الرسائل القديمة في نوافذ مفتوحة بلا صورة فجأة.
       */
      if (path === '/v1/chat/delete' && request.method === 'POST') {
        await rateLimit(env, request, 'chatwrite', 40, 60)
        const body = await request.json<{ id?: string }>()
          .catch(() => ({} as { id?: string }))
        const msgId = String(body.id ?? '').trim().slice(0, 80)
        if (!msgId) throw new HttpError(400, 'معرّف الرسالة مطلوب')
        const row = await env.XDB.prepare(
          'SELECT user_id, room_id, media_key FROM x_chat_messages WHERE id = ?1 AND deleted = 0'
        ).bind(msgId).first<{ user_id: string; room_id: string; media_key: string }>()
        if (!row) throw new HttpError(404, 'الرسالة غير موجودة')
        const meId = chatUser?.id ?? `guest:${caller.uid}`
        // المالك يحذف أي رسالة؛ غيره يحذف رسالته وحدها.
        if (caller.role !== 'owner' && row.user_id !== meId) {
          throw new HttpError(403, 'يمكنك حذف رسائلك وحدها')
        }
        await env.XDB.prepare(
          'UPDATE x_chat_messages SET deleted = 1 WHERE id = ?1'
        ).bind(msgId).run()
        await logSecurity(env, request, 'chat_delete',
          `حذف رسالة ${msgId} في ${row.room_id}${caller.role === 'owner' ? ' (المالك)' : ''}`)
        return json({ ok: true, id: msgId, roomId: row.room_id })
      }

      /**
       * إعلام الخادم أن المستخدم بلغ آخر رسالة في القسم.
       *
       * هذا ما يجعل «من رأى الرسالة» ممكناً: ختم واحد لكل (مستخدم، قسم).
       * ولا يُحرَّك الختم للخلف أبداً، فطلب متأخر لا يمحو مشاهدة سابقة.
       */
      if (path === '/v1/chat/seen' && request.method === 'POST') {
        await rateLimit(env, request, 'chatread', 3000, 600)
        if (!chatUser) return json({ ok: true, skipped: true })
        const body = await request.json<{ room?: string; at?: number }>()
          .catch(() => ({} as { room?: string; at?: number }))
        const roomId = String(body.room ?? '')
        if (!settings.chatRooms.some(r => r.id === roomId)) {
          throw new HttpError(404, 'القسم غير موجود')
        }
        const at = Math.max(0, Math.min(Date.now(), Math.floor(Number(body.at) || 0)))
        if (at <= 0) return json({ ok: true, skipped: true })
        await env.XDB.prepare(
          `INSERT INTO x_chat_seen (user_id, room_id, last_at, seen_at)
           VALUES (?1, ?2, ?3, ?4)
           ON CONFLICT(user_id, room_id) DO UPDATE SET
             last_at = MAX(x_chat_seen.last_at, excluded.last_at),
             seen_at = excluded.seen_at`
        ).bind(chatUser.id, roomId, at, new Date().toISOString()).run()
        return json({ ok: true })
      }

      // إرسال رسالة نصية أو وسيط (صورة/صوت/فيديو).
      if (path === '/v1/chat/send' && request.method === 'POST') {
        await rateLimit(env, request, 'chatwrite', 40, 60)
        if (!settings.chatEnabled) throw new HttpError(403, 'الدردشة موقوفة حالياً')

        const write = chatWriteAllowed(settings, caller, chatUser)
        if (!write.ok) throw new HttpError(403, write.reason)

        // هوية الكاتب: حساب مسجّل، أو هوية الزائر المرتبطة بالجهاز.
        // الزائر هوية دائمة على جهازه (guest_<device>)، ولكنه بلا صف في
        // x_users. استخدام chatUser!.id كان يجعل كتابة الزائر تنهار بخطأ
        // خادم، فصار له معرّف مشتق من الجلسة كما في مسارات القراءة.
        const authorId = chatUser?.id ?? `guest:${caller.uid}`

        // لا كتابة بلا هوية: من يدخل باسم «عضو» يملأ الدردشة بأسماء متطابقة
        // يتعذّر تمييز أصحابها، ولا يمكن ردّ رسالة على أحدهم. الكنية أو الصورة
        // شرط قبل أول رسالة — والمطالبة بها عند الإرسال لا عند القراءة، حتى
        // يبقى التصفّح مفتوحاً لمن لم يقرّر بعد.
        if (caller.role !== 'owner') {
          const prof = await env.XDB.prepare(
            'SELECT nickname, avatar_key FROM x_chat_profiles WHERE user_id = ?1'
          ).bind(authorId)
            .first<{ nickname: string; avatar_key: string }>()
          const hasNick = (prof?.nickname ?? '').trim().length >= 2
          const hasAvatar = (prof?.avatar_key ?? '').length > 0
          if (!hasNick && !hasAvatar) {
            throw new HttpError(403,
              'اختر كنية أو صورة شخصية قبل المراسلة')
          }
        }

        const body = await request.json<{
          room?: string; text?: string; mediaB64?: string
          imageB64?: string; mediaSeconds?: number; waveform?: number[]
          replyTo?: string
        }>().catch(() => ({} as {
          room?: string; text?: string; mediaB64?: string
          imageB64?: string; mediaSeconds?: number; waveform?: number[]
          replyTo?: string
        }))
        const roomId = String(body.room ?? '')
        const room = settings.chatRooms.find(r => r.id === roomId)
        if (!room) throw new HttpError(404, 'القسم غير موجود')

        if (chatUser != null && caller.role !== 'owner') {
          const rest = await chatRestriction(env, chatUser.id, roomId)
          if (rest.kicked) {
            throw new HttpError(403, rest.reason
              ? `تم إخراجك من الدردشة: ${rest.reason}`
              : 'تم إخراجك من الدردشة مؤقتاً')
          }
          if (rest.muted) {
            throw new HttpError(403, rest.reason
              ? `أنت مكتوم: ${rest.reason}`
              : 'أنت مكتوم من الكتابة في الدردشة')
          }
        }

        const text = cleanText(body.text, settings.chatMaxLength)
        // الردّ لا يُقبل إلا على رسالة موجودة **في القسم نفسه**: معرّف من
        // قسم آخر كان يسرّب مقتطفاً من محادثة لا يراها المُرسل.
        let replyTo = String(body.replyTo ?? '').trim().slice(0, 80)
        let replyBody = ''
        let replyKind = 'text'
        let replyName = ''
        if (replyTo) {
          const target = await env.XDB.prepare(
            `SELECT m.body, m.kind, COALESCE(p.nickname, '') AS nickname
             FROM x_chat_messages m
             LEFT JOIN x_chat_profiles p ON p.user_id = m.user_id
             WHERE m.id = ?1 AND m.room_id = ?2 AND m.deleted = 0`
          ).bind(replyTo, roomId)
            .first<{ body: string; kind: string; nickname: string }>()
          if (target) {
            replyBody = (target.body ?? '').slice(0, 240)
            replyKind = target.kind ?? 'text'
            replyName = target.nickname ?? ''
          } else {
            replyTo = ''
          }
        }
        // نستقبل imageB64 القديم أيضاً كي لا تتعطل نسخة مثبّتة سابقة.
        const rawMedia = String(body.mediaB64 ?? body.imageB64 ?? '')
        let kind: ChatKind = 'text'
        let mediaKey = ''
        let mediaMime = ''
        let mediaSize = 0
        // مدة المقطع تُحفظ مع الرسالة: المشغّل يحتاجها لعرض الطول ورسم
        // موضع الموجة قبل بدء التشغيل، وللتحقق من الحد الأقصى للمدة.
        let mediaSeconds = 0

        // مخطط الموجة اختياري وبلا قيمة أمنية: أرقام تُرسم فقط. نطبيعها
        // بدل رفضها — مقطع قديم أو نسخة لا ترسله يبقى يعمل بمخطط افتراضي.
        // 64 نقطة تكفي لعرض شريط صوتي على الجوال، ونطاق 0..1 يكفي للرسم.
        let waveform = ''
        if (Array.isArray(body.waveform) && body.waveform.length) {
          const pts = body.waveform
            .slice(0, 64)
            .map(v => Math.max(0, Math.min(1, Number(v) || 0)))
          if (pts.length) waveform = pts.map(v => v.toFixed(3)).join(',')
        }

        if (rawMedia) {
          const payload = rawMedia.replace(/^data:[^,]+,/, '')
          const maxBytes = settings.chatMaxMediaMb * 1024 * 1024
          // base64 يضخّم 4/3، فنرفض مبكراً قبل فكّه في الذاكرة.
          if (payload.length > Math.ceil(maxBytes * 4 / 3) + 64) {
            throw new HttpError(413, `الملف كبير (أقصى ${settings.chatMaxMediaMb}MB)`)
          }
          let bytes: Uint8Array
          try {
            bytes = Uint8Array.from(atob(payload), c => c.charCodeAt(0))
          } catch {
            throw new HttpError(400, 'صيغة الملف غير صالحة')
          }
          if (bytes.length > maxBytes) {
            throw new HttpError(413, `الملف كبير (أقصى ${settings.chatMaxMediaMb}MB)`)
          }
          const sig = sniffMedia(bytes)
          if (!sig) throw new HttpError(400, 'نوع الملف غير مدعوم')

          if (sig.kind === 'image') {
            if (!settings.chatImagesEnabled) throw new HttpError(403, 'رفع الصور موقوف')
            // الصور متاحة لكل من يكتب، والمقاطع للمشتركين وحدهم.
            if (bytes.length > 3 * 1024 * 1024) {
              throw new HttpError(413, 'الصورة كبيرة (أقصى 3MB)')
            }
          } else {
            const media = chatMediaAllowed(settings, caller, chatUser)
            if (!media.ok) throw new HttpError(403, media.reason)
            const secs = Math.max(0, Math.floor(Number(body.mediaSeconds) || 0))
            // المدة تُتحقق إن أرسلها التطبيق: الحجم وحده لا يمنع مقطعاً
            // طويلاً بجودة منخفضة، والمدة هي ما يثقل التخزين والبث.
            if (secs > settings.chatMediaSeconds) {
              throw new HttpError(413, `المقطع أطول من ${settings.chatMediaSeconds} ثانية`)
            }
            mediaSeconds = secs
          }

          kind = sig.kind
          mediaMime = sig.mime
          mediaSize = bytes.length
          const id = `chat_${uid()}`
          mediaKey = `chat/${roomId}/${id}.${sig.ext}`
          await env.XMEDIA.put(mediaKey, bytes, { httpMetadata: { contentType: sig.mime } })
          const at = Date.now()
          await env.XDB.prepare(
            `INSERT INTO x_chat_messages
               (id, room_id, user_id, kind, body, media_key, media_mime, media_size, created_at, waveform, media_seconds, reply_to)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)`
          ).bind(
            id, roomId, authorId, kind, text, mediaKey, mediaMime, mediaSize, at, waveform, mediaSeconds, replyTo
          ).run()
          const profiles = await chatProfiles(env.XDB, [authorId])
          const authorName = profiles.get(authorId)?.nickname || 'عضو'
          const preview = chatPreview(kind, text, mediaSeconds)
          ctx.waitUntil(pushRoomMessage(
            env, roomId, authorId, authorName, preview,
          ).catch(() => 0))
          return json({
            ok: true,
            message: chatMessageJson({
              id, room_id: roomId, user_id: authorId, kind,
              body: text, media_key: mediaKey, media_mime: mediaMime,
              media_size: mediaSize, created_at: at, waveform,
              media_seconds: mediaSeconds, reply_to: replyTo,
              reply_to_body: replyBody, reply_to_kind: replyKind,
              reply_to_name: replyName,
            }, profiles.get(authorId), authorId),
          })
        }

        if (!text) throw new HttpError(400, 'اكتب رسالة أولاً')
        const id = `chat_${uid()}`
        const at = Date.now()
        await env.XDB.prepare(
          `INSERT INTO x_chat_messages
             (id, room_id, user_id, kind, body, media_key, media_mime, media_size, created_at, reply_to)
           VALUES (?1, ?2, ?3, ?4, ?5, '', '', 0, ?6, ?7)`
        ).bind(id, roomId, authorId, kind, text, at, replyTo).run()
        const profiles = await chatProfiles(env.XDB, [authorId])
        const authorName = profiles.get(authorId)?.nickname || 'عضو'
        ctx.waitUntil(pushRoomMessage(
          env, roomId, authorId, authorName, chatPreview(kind, text, 0),
        ).catch(() => 0))
        return json({
          ok: true,
          message: chatMessageJson({
            id, room_id: roomId, user_id: authorId, kind,
            body: text, media_key: '', media_mime: '', media_size: 0, created_at: at,
            reply_to: replyTo, reply_to_body: replyBody, reply_to_kind: replyKind,
            reply_to_name: replyName,
          }, profiles.get(authorId), authorId),
        })
      }

      /**
       * ── رفع مقاطع الدردشة على أجزاء ──
       *
       * لماذا لا يمرّ المقطع الكبير في /v1/chat/send كما الصور؟ لأن الصوت
       * والفيديو يُرسلان base64 داخل JSON، والحشو يضخّم الحجم 4/3 ويوضع
       * كاملاً في ذاكرة العامل، فمقطع 50MB ينهي الطلب. هذا المسار يدفق
       * البايتات إلى R2 جزءاً جزءاً بلا حشو وبلا تحميل كامل في الذاكرة.
       *
       * الصلاحية نفسها المطبَّقة على الإرسال: `chatWriteAllowed` ثم
       * `chatMediaAllowed` — أي أن المالك مسموح دائماً، وغيره حسب الإعداد.
       */
      if (path === '/v1/chat/upload/init' && request.method === 'POST') {
        await rateLimit(env, request, 'chatwrite', 40, 60)
        if (!settings.chatEnabled) throw new HttpError(403, 'الدردشة موقوفة حالياً')
        const write = chatWriteAllowed(settings, caller, chatUser)
        if (!write.ok) throw new HttpError(403, write.reason)
        const media = chatMediaAllowed(settings, caller, chatUser)
        if (!media.ok) throw new HttpError(403, media.reason)

        const b = await request.json<any>().catch(() => ({}))
        const roomId = String(b.room ?? '')
        if (!settings.chatRooms.some(r => r.id === roomId)) {
          throw new HttpError(404, 'القسم غير موجود')
        }
        const authorId = chatUser?.id ?? `guest:${caller.uid}`
        const size = Math.max(0, Math.floor(Number(b.size) || 0))
        const cap = settings.chatMaxMediaMb * 1024 * 1024
        if (size > cap) {
          throw new HttpError(413, `الملف كبير (أقصى ${settings.chatMaxMediaMb}MB)`)
        }
        const seconds = Math.max(0, Math.floor(Number(b.seconds) || 0))
        if (seconds > settings.chatMediaSeconds) {
          throw new HttpError(413, `المقطع أطول من ${settings.chatMediaSeconds} ثانية`)
        }
        const audio = String(b.kind ?? '') === 'audio'
        const name = String(b.name ?? '').toLowerCase()
        const extMatch = name.match(/\.(mp4|m4v|mov|webm|mkv|m4a|aac|mp3|ogg|opus|wav)$/)
        const ext = extMatch ? extMatch[1] : (audio ? 'm4a' : 'mp4')
        const declared = String(b.mime ?? '').slice(0, 60)
        const mime = declared.startsWith(audio ? 'audio/' : 'video/')
          ? declared
          : (audio ? 'audio/mp4' : 'video/mp4')

        const uploadId = `cu_${uid()}`
        const objectKey = `chat/${roomId}/${uploadId}.${ext}`
        const mp = await env.XMEDIA.createMultipartUpload(objectKey, {
          httpMetadata: { contentType: mime },
        })
        // الرسالة المُقتبَسة تُتحقق هنا أيضاً كي لا تكتمل جلسة ثم يُرفض الردّ.
        const replyTo = String(b.replyTo ?? '').trim().slice(0, 80)
        if (replyTo) {
          const target = await env.XDB.prepare(
            'SELECT id FROM x_chat_messages WHERE id = ?1 AND room_id = ?2 AND deleted = 0'
          ).bind(replyTo, roomId).first<{ id: string }>()
          if (!target) throw new HttpError(404, 'الرسالة المقتبَسة غير موجودة')
        }
        await env.XDB.prepare(
          `INSERT INTO x_chat_uploads (id, room_id, user_id, object_key, r2_upload_id,
             kind, mime, size_bytes, seconds, reply_to, text, parts_done, created_at)
           VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,0,?12)`
        ).bind(uploadId, roomId, authorId, objectKey, mp.uploadId,
               audio ? 'audio' : 'video', mime, size, seconds, replyTo,
               cleanText(b.text, settings.chatMaxLength),
               new Date().toISOString()).run()
        return json({ ok: true, uploadId, objectKey, chunk: CHAT_UPLOAD_CHUNK })
      }

      const chatPart = path.match(/^\/v1\/chat\/upload\/(cu_[\w]+)\/part\/(\d{1,5})$/)
      if (chatPart && request.method === 'PUT') {
        await rateLimit(env, request, 'chatwrite', 600, 60)
        const upload = await env.XDB.prepare(
          'SELECT * FROM x_chat_uploads WHERE id = ?1'
        ).bind(chatPart[1]).first<any>()
        if (!upload) throw new HttpError(404, 'جلسة الرفع غير موجودة')
        const authorId = chatUser?.id ?? `guest:${caller.uid}`
        if (upload.user_id !== authorId) {
          throw new HttpError(403, 'جلسة رفع تخصّ غيرك')
        }
        const partNo = Number(chatPart[2])
        if (partNo < 1 || partNo > 10000) throw new HttpError(400, 'رقم الجزء غير صالح')
        if (!request.body) throw new HttpError(400, 'لا يوجد جزء')
        const mp = env.XMEDIA.resumeMultipartUpload(upload.object_key, upload.r2_upload_id)
        const uploaded = await mp.uploadPart(partNo, request.body)
        await env.XDB.prepare(
          'UPDATE x_chat_uploads SET parts_done = MAX(parts_done, ?1) WHERE id = ?2'
        ).bind(partNo, chatPart[1]).run()
        return json({ ok: true, part: partNo, etag: uploaded.etag })
      }

      if (path === '/v1/chat/upload/complete' && request.method === 'POST') {
        await rateLimit(env, request, 'chatwrite', 40, 60)
        const b = await request.json<any>().catch(() => ({}))
        const upId = String(b.uploadId ?? '')
        const upload = await env.XDB.prepare(
          'SELECT * FROM x_chat_uploads WHERE id = ?1'
        ).bind(upId).first<any>()
        if (!upload) throw new HttpError(404, 'جلسة الرفع غير موجودة')
        const authorId = chatUser?.id ?? `guest:${caller.uid}`
        if (upload.user_id !== authorId) {
          throw new HttpError(403, 'جلسة رفع تخصّ غيرك')
        }
        const parts = Array.isArray(b.parts)
          ? b.parts
              .map((p: any) => ({ partNumber: Number(p.partNumber), etag: String(p.etag) }))
              .filter((p: any) => p.partNumber >= 1 && p.etag)
              .sort((a: any, c: any) => a.partNumber - c.partNumber)
          : []
        if (!parts.length) throw new HttpError(400, 'لا توجد أجزاء للإكمال')

        const mp = env.XMEDIA.resumeMultipartUpload(upload.object_key, upload.r2_upload_id)
        const obj = await mp.complete(parts)
        const size = (obj as any)?.size ?? upload.size_bytes
        // تحقق نهائي من النوع على أول بايتات الكائن: الترويسة التي أعلنها
        // العميل ليست دليلاً، وقبول أي شيء يحوّل الدلو إلى مزبلة ملفات.
        try {
          const head = await env.XMEDIA.get(upload.object_key, { range: { offset: 0, length: 32 } })
          const sig = head ? sniffMedia(new Uint8Array(await head.arrayBuffer())) : null
          if (!sig || sig.kind !== upload.kind) {
            await env.XMEDIA.delete(upload.object_key)
            await env.XDB.prepare('DELETE FROM x_chat_uploads WHERE id = ?1').bind(upId).run()
            throw new HttpError(400, 'نوع الملف غير مدعوم')
          }
        } catch (e) {
          if (e instanceof HttpError) throw e
          // فشل قراءة الترويسة لا يُسقط الرفع: الملف قد يكون سليماً وتعذّر
          // الفحص فقط. نُكمل ونعتمد إعلان العميل بدل إتلاف مقطع صحيح.
        }

        const id = `chat_${uid()}`
        const at = Date.now()
        // المقتطف يُبنى الآن من الرسالة المقتبَسة كما في مسار الإرسال المباشر.
        let replyBody = ''
        let replyKind = 'text'
        let replyName = ''
        let replyTo = upload.reply_to ?? ''
        if (replyTo) {
          const target = await env.XDB.prepare(
            `SELECT m.body, m.kind, COALESCE(p.nickname, '') AS nickname
             FROM x_chat_messages m
             LEFT JOIN x_chat_profiles p ON p.user_id = m.user_id
             WHERE m.id = ?1 AND m.room_id = ?2 AND m.deleted = 0`
          ).bind(replyTo, upload.room_id)
            .first<{ body: string; kind: string; nickname: string }>()
          if (target) {
            replyBody = (target.body ?? '').slice(0, 240)
            replyKind = target.kind ?? 'text'
            replyName = target.nickname ?? ''
          } else {
            replyTo = ''
          }
        }
        await env.XDB.prepare(
          `INSERT INTO x_chat_messages
             (id, room_id, user_id, kind, body, media_key, media_mime, media_size,
              created_at, media_seconds, reply_to)
           VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)`
        ).bind(id, upload.room_id, authorId, upload.kind, upload.text ?? '',
               upload.object_key, upload.mime, size, at,
               upload.seconds ?? 0, replyTo).run()
        await env.XDB.prepare('DELETE FROM x_chat_uploads WHERE id = ?1').bind(upId).run()

        const profiles = await chatProfiles(env.XDB, [authorId])
        const authorName = profiles.get(authorId)?.nickname || 'عضو'
        ctx.waitUntil(pushRoomMessage(
          env, upload.room_id, authorId, authorName,
          chatPreview(upload.kind, upload.text ?? '', upload.seconds ?? 0),
        ).catch(() => 0))
        return json({
          ok: true,
          message: chatMessageJson({
            id, room_id: upload.room_id, user_id: authorId, kind: upload.kind,
            body: upload.text ?? '', media_key: upload.object_key,
            media_mime: upload.mime, media_size: size, created_at: at,
            media_seconds: upload.seconds ?? 0, reply_to: replyTo,
            reply_to_body: replyBody, reply_to_kind: replyKind,
            reply_to_name: replyName,
          }, profiles.get(authorId), authorId),
        })
      }

      if (path === '/v1/chat/upload/abort' && request.method === 'POST') {
        await rateLimit(env, request, 'chatwrite', 60, 60)
        const b = await request.json<any>().catch(() => ({}))
        const upId = String(b.uploadId ?? '')
        const upload = await env.XDB.prepare(
          'SELECT * FROM x_chat_uploads WHERE id = ?1'
        ).bind(upId).first<any>()
        if (!upload) return json({ ok: true, skipped: true })
        const authorId = chatUser?.id ?? `guest:${caller.uid}`
        if (upload.user_id !== authorId) {
          throw new HttpError(403, 'جلسة رفع تخصّ غيرك')
        }
        try {
          const mp = env.XMEDIA.resumeMultipartUpload(upload.object_key, upload.r2_upload_id)
          await mp.abort()
        } catch { /* الرفع قد أُكمل أو أُبطل سابقاً */ }
        await env.XDB.prepare('DELETE FROM x_chat_uploads WHERE id = ?1').bind(upId).run()
        return json({ ok: true })
      }

      /**
       * تسجيل رمز جهاز الدفع.
       *
       * يُستدعى كلما أمكن الحصول على رمز (عند الإقلاع، وبعد كل تدوير رمز)
       * والحفظ `INSERT OR REPLACE` لأن الرمز قد ينتقل بين مستخدمين على الجهاز
       * نفسه — تسجيل دخول آخر يملك الرمز، والقديم يجب ألا يبقى مالكاً له.
       */
      if (path === '/v1/push/register' && request.method === 'POST') {
        await rateLimit(env, request, 'chatwrite', 40, 60)
        const body = await request.json() as { token?: string; platform?: string }
        const token = (body.token ?? '').trim()
        // الرمز يأتي من FCM وطوله يتجاوز المئة؛ نرفض القصير الواضح أنه ليس رمزاً
        // بدل تخزين قيم عابثة تُثقل كل إرسال لاحق.
        if (token.length < 20 || token.length > 4096) {
          throw new HttpError(400, 'رمز الدفع غير صالح')
        }
        const meId = chatUser?.id ?? `guest:${caller.uid}`
        await env.XDB.prepare(
          `INSERT INTO x_push_tokens (token, user_id, platform, updated_at)
           VALUES (?1, ?2, ?3, ?4)
           ON CONFLICT(token) DO UPDATE SET
             user_id = excluded.user_id,
             platform = excluded.platform,
             updated_at = excluded.updated_at`
        ).bind(
          token, meId,
          (body.platform ?? 'android').slice(0, 16),
          new Date().toISOString(),
        ).run()
        return json({ ok: true, push: pushEnabled(env) })
      }

      // إلغاء التسجيل عند تسجيل الخروج: بلا هذا يظل الجهاز يستقبل إشعارات
      // حسابٍ لم يعد يستخدمه.
      if (path === '/v1/push/unregister' && request.method === 'POST') {
        await rateLimit(env, request, 'chatwrite', 40, 60)
        const body = await request.json() as { token?: string }
        const token = (body.token ?? '').trim()
        if (token) {
          await env.XDB.prepare('DELETE FROM x_push_tokens WHERE token = ?1')
            .bind(token).run()
        }
        return json({ ok: true })
      }

      // ملف الدردشة: كنية، صورة شخصية، وكتم الإشعارات من جهة المستخدم.
      // الكنية تُنقّى من محارف الاتجاه حتى لا ينتحل أحد اسم غيره بتشكيل بصري.
      if (path === '/v1/chat/profile' && request.method === 'PUT') {
        await rateLimit(env, request, 'chatwrite', 40, 60)
        // الزائر يحتاج ملفاً تعريفياً أيضاً: شرط «كنية أو صورة» قبل الكتابة
        // يسري عليه، فحجبه هنا يجعله عاجزاً عن تجاوز الشرط أصلاً.
        const authorId = chatUser?.id ?? `guest:${caller.uid}`
        // المالك لا يحتاج ملفاً تعريفياً، وغياب جلسة صالحة يمنع البقية.
        if (caller.role !== 'owner' && !caller.uid) {
          throw new HttpError(403, 'جلسة غير صالحة')
        }
        const body = await request.json<{
          nickname?: string; imageB64?: string; clearAvatar?: boolean; notify?: boolean
        }>().catch(() => ({} as {
          nickname?: string; imageB64?: string; clearAvatar?: boolean; notify?: boolean
        }))

        const nickname = cleanText(body.nickname, 24)
        let avatarKey: string | null = null
        if (body.imageB64) {
          const raw = String(body.imageB64).replace(/^data:[^,]+,/, '')
          if (raw.length > 3 * 1024 * 1024) throw new HttpError(413, 'الصورة كبيرة (أقصى 1.5MB)')
          let bytes: Uint8Array
          try {
            bytes = Uint8Array.from(atob(raw), c => c.charCodeAt(0))
          } catch {
            throw new HttpError(400, 'صيغة الصورة غير صالحة')
          }
          if (bytes.length > 1.5 * 1024 * 1024) throw new HttpError(413, 'الصورة كبيرة (أقصى 1.5MB)')
          const sig = sniffMedia(bytes)
          if (!sig || sig.kind !== 'image') throw new HttpError(400, 'الملف ليس صورة صالحة')
          avatarKey = `chat/avatars/${authorId}.${sig.ext}`
          await env.XMEDIA.put(avatarKey, bytes, { httpMetadata: { contentType: sig.mime } })
        } else if (body.clearAvatar) {
          avatarKey = ''
        }

        const cur = await env.XDB.prepare(
          'SELECT nickname, avatar_key, notify FROM x_chat_profiles WHERE user_id = ?1'
        ).bind(authorId).first<{ nickname: string; avatar_key: string; notify: number }>()

        const nextNick = body.nickname === undefined ? (cur?.nickname ?? '') : nickname
        const nextAvatar = avatarKey === null ? (cur?.avatar_key ?? '') : avatarKey
        const nextNotify = body.notify === undefined
          ? (cur?.notify ?? 1)
          : (body.notify ? 1 : 0)
        await env.XDB.prepare(
          `INSERT INTO x_chat_profiles (user_id, nickname, avatar_key, notify, updated_at)
           VALUES (?1, ?2, ?3, ?4, ?5)
           ON CONFLICT(user_id) DO UPDATE SET
             nickname = excluded.nickname,
             avatar_key = excluded.avatar_key,
             notify = excluded.notify,
             updated_at = excluded.updated_at`
        ).bind(
          authorId, nextNick, nextAvatar, nextNotify, new Date().toISOString()
        ).run()

        return json({
          ok: true,
          nickname: nextNick,
          avatarUrl: nextAvatar ? `/v1/media/${nextAvatar}` : '',
          notify: nextNotify === 1,
        })
      }





      // ---------- وسائط الإعلانات (صور ترفعها اللوحة) ----------

      const mediaMatch = path.match(/^\/v1\/media\/(.+)$/)
      if (mediaMatch && request.method === 'GET') {
        const key = decodeURIComponent(mediaMatch[1])
        if (!/^[\w\-./]{3,200}$/.test(key) || key.includes('..')) throw new HttpError(400, 'bad key')
        const obj = await env.XMEDIA.get(key)
        if (!obj?.body) throw new HttpError(404, 'not found')
        const headers = new Headers()
        obj.writeHttpMetadata(headers)
        // محتوى الدردشة خاص بمستخدمي التطبيق: `private` يمنع أي وسيط مشترك
        // من الاحتفاظ بصور الأعضاء، بخلاف صور الإعلانات التي يجوز كاشها.
        headers.set('cache-control', key.startsWith('chat/')
          ? 'private, max-age=86400'
          : 'public, max-age=86400')
        return new Response(obj.body, { headers })
      }

// ---------- أكاديمية الدورات ----------

      // مصغّرة الفيديو: صورة واجهة اختيارية لكل درس.
      //
      // كانت تُستعمل في التطبيق بلا أي حقل مصدر، فلا يوجد ما يُعرض. تُخدم هنا
      // بلا شرط استحقاق — المصغّرة لا تكشف المقطع، ووجودها على الدرس المقفل
      // (مع قفل واضح) هو ما يسمح للمستخدم بأن يقرّر ما يفتحه.
      const thumbMatch = path.match(/^\/v1\/learn\/thumb\/([\w-]{1,64})$/)
      if (thumbMatch && request.method === 'GET') {
        await rateLimit(env, request, 'learn_cover', 300, 600)
        const video = await env.XDB
          .prepare('SELECT thumb_key FROM x_course_videos WHERE id = ?1 AND published = 1')
          .bind(thumbMatch[1]).first<{ thumb_key: string }>()
        if (!video?.thumb_key) throw new HttpError(404, 'لا توجد مصغّرة')
        const obj = await env.XLEARN.get(video.thumb_key)
        if (!obj?.body) throw new HttpError(404, 'المصغّرة مفقودة')
        const headers = new Headers()
        obj.writeHttpMetadata(headers)
        headers.set('cache-control', 'public, max-age=86400')
        return new Response(obj.body, { headers })
      }

      // ---------- هديّة الحصة اليومية ----------
      //
      // زر واحد يمنح عملات محسومة من الخادم. القيمة تأتي من إعدادات المالك
      // لا من العميل، والمفتاح اليومي يجعل المنح مرة واحدة في اليوم لكل
      // محفظة. لا يمكن للعميل اختيار المبلغ ولا تكرار الطلب.
      if (path === '/v1/gift/claim' && request.method === 'POST') {
        await rateLimit(env, request, 'gift_claim', 20, 3600)
        const fp = await walletOf(env, request)
        const amount = Math.max(0, Math.min(1000,
          Math.floor(Number(settings.dailyFreeQuota) || 0)))
        if (amount <= 0) {
          return json({ ok: false, error: 'الهديّة معطّلة حالياً', status: 403 }, 403)
        }
        // الحجز ذرّي على صفّ المحفظة وحده: الشرط `next_at <= now` داخل UPDATE
        // يعني أن طلبين متزامنين لا يمنحان الهديّة مرتين — الثاني لا يجد صفاً
        // يُحدَّث فيفشل بلا منح.
        //
        // النافذة 24 ساعة من لحظة الاستلام لا يوم تقويمي: مع مفتاح اليوم كان
        // من يستلم الساعة 23:00 يفقد هديّته بعد ساعة، ومن يستلم 00:05 يُمنع
        // 24 ساعة — أي هديّتان في يوم واحد أو واحدة في يومين حسب التوقيت.
        const nowMs = Date.now()
        const nextMs = nowMs + DAY * 1000
        if (caller.role !== 'user' && caller.role !== 'guest') {
          throw new HttpError(403, 'الحصة متاحة للمستخدمين والزوار فقط')
        }
        if (await fingerprintRotated(env, request, caller)) {
          throw new HttpError(403, 'تعذر تأكيد هوية المحفظة')
        }
        const stamp = new Date(nowMs).toISOString()
        // الثغرة التي أُغلقت: الاستلام كان مفتاحه المحفظة فقط، ومسح بيانات
        // التطبيق يولّد تثبيتاً جديداً فتُخلق له محفظة `in:` جديدة فتُمنح
        // الهديّة مرة أخرى لنفس الجهاز. البصمة (ANDROID_ID) تبقى بعد المسح
        // وإعادة التثبيت، فالاستلام يُحجز عليها أيضاً: جهاز واحد = هديّة
        // واحدة في اليوم مهما أُعيد التثبيت. من زوّر بصمة عشوائية جديدة
        // يحصل محفظة جديدة خاوية — لكن لا هديّة إضافية على بصمة مستعملة.
        const claimSql =
          `INSERT INTO x_gift_claims (wallet, last_at, next_at, updated_at)
           VALUES (?1, ?2, ?3, ?4)
           ON CONFLICT(wallet) DO UPDATE SET last_at = ?2, next_at = ?3, updated_at = ?4
           WHERE next_at <= ?2 AND last_at <= ?5
           RETURNING wallet`
        const fpRaw = fingerprint(request)
        // حجز البصمة أولاً ومنفرداً: لو دخل في نفس الدفعة مع الإيداع لأُودعت
        // العملات ثم اكتشفنا أن الجهاز استلم — رصيد بلا استحقاق. الفشل هنا
        // يرفض الطلب قبل أن تتحرك أي عملة.
        if (fpRaw.startsWith('fp:') && fpRaw !== fp) {
          const fpClaim = await env.XDB.prepare(claimSql)
            .bind(fpRaw, nowMs, nextMs, stamp, nowMs - DAY * 1000).run()
          if (!fpClaim.results.length) {
            return json({
              ok: false,
              error: 'يمكن استلام الحصة مرة كل 24 ساعة',
              status: 409
            }, 409)
          }
        }
        const claim = env.XDB.prepare(claimSql)
          .bind(fp, nowMs, nextMs, stamp, nowMs - DAY * 1000)
        // الجدول غير موجود بعد على قاعدة لم تُحدَّث: لا نُسقط الاستلام،
        // ونرجع للمفتاح اليومي كي تبقى الهديّة تعمل بلا انقطاع.
        // الإيداع في المحفظة الحقيقية: مشترك في رصيده، وزائر في محفظته.
        const credit = caller.role === 'user'
          ? env.XDB.prepare(
              `UPDATE x_users SET
                 quota_balance = CASE WHEN quota_expires_at > 0 AND quota_expires_at <= ?3
                   THEN ?2 ELSE quota_balance + ?2 END,
                 quota_expires_at = CASE WHEN quota_expires_at > 0 AND quota_expires_at <= ?3
                   THEN 0 ELSE quota_expires_at END
               WHERE id = ?1 AND changes() = 1 RETURNING quota_balance AS balance`
            ).bind(caller.uid, amount, nowMs)
          : env.XDB.prepare(
              `INSERT INTO x_guest_wallets (device_id, balance, expires_at, created_at, updated_at)
               SELECT ?1, ?2, 0, ?3, ?3 WHERE changes() = 1
               ON CONFLICT(device_id) DO UPDATE SET
                 balance = CASE WHEN expires_at > 0 AND expires_at <= ?4
                   THEN ?2 ELSE balance + ?2 END,
                 expires_at = CASE WHEN expires_at > 0 AND expires_at <= ?4
                   THEN 0 ELSE expires_at END,
                 updated_at = ?3
               RETURNING balance`
            ).bind(fp, amount, stamp, nowMs)
        const result = await env.XDB.batch([claim, credit])
        if (!result[0].results.length) {
          return json({ ok: false, error: 'يمكن استلام الحصة مرة كل 24 ساعة', status: 409 }, 409)
        }
        const balance = Number((result[1].results[0] as { balance: number }).balance)
        await logSecurity(env, request, 'gift_claim', `amount=${amount} role=${caller.role}`)
        return json({
          ok: true, amount, balance, nextAt: nextMs,
          message: `حصلت على ${amount} عملة هديّة اليوم`,
        })
      }

      // ---------- الإفراج عن جهاز مالك ----------
      // بلا هذا المسار يُقفل المالك خارج لوحته إن بلغ السقف وفقد هاتفاً.
      if (path === '/v1/owner/devices/release' && request.method === 'POST') {
        const auth = await authenticate(env, request)
        if (auth.caller.role !== 'owner') throw new HttpError(403, 'forbidden')
        const body = await request.json<any>().catch(() => ({}))
        // الوسم مفتاحه install_id الآن. يُقبل deviceId للتوافق مع لوحة
        // قديمة، لكن يُترجم إلى install_id أولاً: تمريره كما هو كان يفرّغ
        // صفاً غير موجود فيبدو الإفراج ناجحاً والخانة مشغولة.
        const installId = String(body.installId ?? '').trim()
        const deviceId = String(body.deviceId ?? '').trim()
        if (!/^[\w-]{8,80}$/.test(installId) && !/^[\w-]{8,64}$/.test(deviceId)) {
          throw new HttpError(400, 'installId مطلوب')
        }
        let target = installId
        if (!target) {
          const row = await env.XDB.prepare(
            'SELECT install_id FROM x_devices WHERE device_id = ?1 LIMIT 1'
          ).bind(deviceId).first<{ install_id: string }>()
          target = row?.install_id ?? ''
        }
        if (!target) throw new HttpError(404, 'التثبيت غير موجود')
        await releaseOwnerDevice(env, target)
        await logSecurity(env, request, 'owner_device_release', `target=${target.slice(0, 10)}`)
        return json({ ok: true })
      }

      // ---------- سحب وسم جهاز المالك ----------
      // عند الخروج من اللوحة تُحرَّر الخانة كاملة (الوسم والربط معاً):
      // تحرير الوسم وحده كان يترك owner_bound مشغولاً للأبد، فتتراكم
      // تثبيتات محذوفة حتى يُقفل المالك خارج لوحته عند السقف 3 — وهو ما
      // حدث فعلاً. تحرير الربط عند الخروج لا يُضعف الحدّ: السقف يبقى على
      // الأجهزة المتزامنة، والدخول يظل يحتاج كلمة مرور المالك.
      if (path === '/v1/owner/device/release' && request.method === 'POST') {
        const auth = await authenticate(env, request)
        if (auth.caller.role !== 'owner') throw new HttpError(403, 'forbidden')
        await releaseOwnerDevice(env, verifiedInstallOf(request))
        await logSecurity(env, request, 'owner_device_release')
        return json({ ok: true })
      }

      if (path === '/v1/learn/courses' && request.method === 'GET') {
        await rateLimit(env, request, 'learn_list', 240, 600)
        const installId = verifiedInstallOf(request)
        const list = await coursesFor(env, installId,
          await ownerDevice(env, installId), settings.videosHidden)
        return json(
          { courses: list, telegramUrl: settings.telegramLink },
          200,
          { 'cache-control': 'no-store' }
        )
      }

      // تفعيل مفتاح. الخادم هو من يقرر: يستقبل الكود، يجزّئه، يطابقه،
      // ويربط التمكين بالجهاز. الكود لا يُخزَّن صريحاً في أي رد أو سجل.
      if (path === '/v1/learn/redeem' && request.method === 'POST') {
        await rateLimit(env, request, 'learn_redeem', 10, 600)
        // المنحة تُنسب إلى التثبيت الموثّق: `x-device-id` كان يكفي لفتح
        // أي دورة بلا كود أصلاً، لأن من قرأ معرّف جهاز مشترك يضعه في طلبه.
        const installId = verifiedInstallOf(request)
        if (!installId) throw new HttpError(403, 'طلب غير موثّق')
        const dev = deviceOf(request)
        const body = await request.json().catch(() => ({})) as { code?: string }
        const code = String(body.code ?? '').trim()
        // 20 محرفاً + شرطات. رفض الشكل أولاً يمنع إغراق القاعدة بمحاولات.
        if (!/^[A-Za-z0-9-]{16,32}$/.test(code)) {
          throw new HttpError(400, 'كود غير صالح')
        }
        const hash = await keyHash(code)
        const key = await env.XDB
          .prepare('SELECT * FROM x_course_keys WHERE code_hash = ?1')
          .bind(hash).first<any>()
        if (!key || key.revoked) {
          await logSecurity(env, request, 'learn_bad_key', `install=${installId}`)
          throw new HttpError(404, 'كود غير صحيح أو ملغى')
        }
        if (key.expires_at > 0 && Date.now() > key.expires_at) {
          throw new HttpError(410, 'انتهت صلاحية الكود')
        }
        const already = await env.XDB
          .prepare('SELECT 1 x FROM x_course_grants WHERE install_id = ?1 AND course_id = ?2')
          .bind(installId, key.course_id).first<{ x: number }>()
        if (!already) {
          // المفتاح لدورة واحدة: الربط بمفتاح واحد يمنع استخدام الكود نفسه
          // على عدة دورات، وmax_uses يحدّ عدد الأجهزة (1 افتراضياً).
          //
          // الحجز والزيادة في جملة UPDATE واحدة مشروطة بـ`used_count <
          // max_uses`. الفحص المنفصل السابق كان سباقاً: جهازان يفكّان نفس
          // الكود في اللحظة نفسها يقرآن `used_count = 0` كلاهما فيمرّان،
          // فيُفتح الكود على عدد أجهزة بلا حد. الآن من يخسر السباق لا
          // يُحدَّث صفّه ولا يحصل على منحة.
          const claimed = await env.XDB.prepare(
            `UPDATE x_course_keys
                SET used_count = used_count + 1, device_id = ?1, used_at = ?2
              WHERE id = ?3 AND used_count < max_uses
              RETURNING used_count`
          ).bind(dev || installId, new Date().toISOString(), key.id)
            .first<{ used_count: number }>()
          if (!claimed) {
            await logSecurity(env, request, 'learn_key_exhausted', `key=${key.id}`)
            throw new HttpError(409, 'الكود مستخدم على جهاز آخر')
          }
          await env.XDB.prepare(
            `INSERT INTO x_course_grants (install_id, device_id, course_id, key_id, user_id, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(install_id, course_id) DO NOTHING`
          ).bind(installId, dev, key.course_id, key.id, caller.uid, Date.now()).run()
        }
        const course = await env.XDB
          .prepare('SELECT title FROM x_courses WHERE id = ?1')
          .bind(key.course_id).first<{ title: string }>()
        return json({
          ok: true,
          courseId: key.course_id,
          courseTitle: course?.title ?? '',
          message: 'تم فتح الدورة على هذا الجهاز'
        })
      }

      // بث الفيديو مباشرة من R2. الهوية إمّا رمز رابط موقّع بالخادم (أصدره
      // بعد فحص الاستحقاق في ردّ الدورات) أو توقيع ترويسات من عميل قديم
      // عبر الوكيل. الاثنان ينتهيان إلى installId موثّق، وعليه وحده يُحسم
      // الاستحقاق — لا شيء مرسلاً يُصدَّق.
      const streamMatch = path.match(/^\/v1\/learn\/stream\/([\w-]{1,64})$/)
      if (streamMatch && request.method === 'GET') {
        // طلبات المدى كثيرة بطبيعتها — الحدّ أوسع من بقية المسارات لكنه
        // يقيس التنوّع لا الحجم: قطعة متابعة لا تكلّف كطلب جديد.
        await Promise.all([
          rateLimit(env, request, 'learn_stream', 480, 600),
          burstLimit(env, request, 'learn_stream', 60)
        ])
        const video = await env.XDB
          .prepare(`SELECT id, course_id, object_key, mime, mode
                    FROM x_course_videos WHERE id = ?1 AND published = 1`)
          .bind(streamMatch[1]).first<any>()
        if (!video) throw new HttpError(404, 'الفيديو غير موجود')

        // الرابط الموقّع يحمل installId الذي صدر له. توقيع الترويسات
        // (المسار القديم) يعطي installId الموثّق في البوابة. بلا أيٍّ منهما
        // لا بثّ — فالطلب مجهول تماماً.
        let installId = verifiedInstallOf(request)
        const tokUrl = new URL(request.url)
        if (tokUrl.searchParams.has('s')) {
          const tokInstall = await verifyLearnToken(env, request, video.id)
          if (!tokInstall) {
            await logSecurity(env, request, 'learn_bad_token', `video=${video.id}`)
            throw new HttpError(403, 'رابط البثّ غير صالح أو انتهى — حدّث قائمة الدروس')
          }
          installId = tokInstall
        }
        if (!installId) throw new HttpError(403, 'طلب غير موثّق')

        // الاستحقاق يُقرأ من الخادم: الفيديو المجاني متاح للجميع، والمقفل
        // يحتاج دورة مفعّلة على هذا الجهاز. لا يهم ما يدّعيه العميل.
        // لا مباح إلا ما وُسم مجاناً، أو دورة استحقّها هذا الجهاز، أو
        // جهاز المالك نفسه. الدور وحده لا يفتح شيئاً: من سجّل بحساب المالك
        // على جهاز آخر لا يرث استحقاقه.
        const allowed = video.mode === 'free' ||
          await courseUnlocked(env, installId, video.course_id) ||
          await ownerDevice(env, installId)
        if (!allowed) {
          await logSecurity(env, request, 'learn_locked_stream', `video=${video.id} install=${installId}`)
          throw new HttpError(403, 'هذا الفيديو مقفل — افتح الدورة بمفتاح')
        }

        // مفتاح الإيقاف يُفحص هنا أيضاً لا في القائمة وحدها: من حفظ رابط البثّ
        // قبل الإيقاف لا بد أن يتوقف عنده أيضاً، وإلا صار المفتاح تجميلياً.
        if (settings.videosHidden) {
          throw new HttpError(403, settings.videosHiddenMessage || 'الفيديوهات متوقفة مؤقتاً')
        }

        // بيانات الملف أولاً بلا جسم: `head` يعيد الحجم والوجود في جلبة
        // واحدة رخيصة، والجسم نفسه يُجلب لاحقاً بالمدى المطلوب فقط.
        const meta = await env.XLEARN.head(video.object_key)
        if (!meta) {
          await logSecurity(env, request, 'learn_stream_missing',
            `video=${video.id} key=${video.object_key}`)
          throw new HttpError(404, 'ملف الفيديو مفقود')
        }
        const mime = video.mime || 'video/mp4'

        // دعم Range: المشغّل يطلب البداية القليلة ليعرض فوراً ثم يواصل الباقي
        // في الخلفية. نمرّر المدى إلى R2 نفسه بدل تنزيل الملف كاملاً.
        const size = meta.size ?? 0
        let start = 0
        let end = size > 0 ? size - 1 : 0
        let partial = false
        const rangeHeader = request.headers.get('range')?.trim()
        if (rangeHeader && size > 0) {
          const m = /^bytes=(\d*)-(\d*)$/.exec(rangeHeader)
          if (m && (m[1] || m[2])) {
            if (m[1]) {
              start = Number(m[1])
              if (m[2]) end = Number(m[2])
            } else {
              start = Math.max(0, size - Number(m[2]))
            }
            end = Math.min(end, size - 1)
            partial = !(start === 0 && end === size - 1)
          }
        }
        if (size > 0 && (start > end || start >= size)) {
          return new Response(null, {
            status: 416,
            headers: { 'content-range': `bytes */${size}` }
          })
        }
        // تشخيص البثّ: نسجّل بداية التشغيل فقط (start=0) — يكفي لمعرفة
        // أن الطلب وصل وأن الرمز والاستحقاق والملف كلها سليمة، ولا نغرق
        // السجل بعشرات طلبات القطع التي يرسلها المشغّل لكل مقطع.
        if (start === 0) {
          // تشخيص البداية: أول 256 بايت تكفي لمشي صناديق MP4 الأولى. لو
          // ظهر `mdat` قبل `moov` فالفهرس في نهاية الملف — والمشغّل على
          // شبكة ضعيفة يبتلع الملف حتى نهايته قبل أول إطار، وهذا هو بطء
          // «جار تجهيز الفيديو» الحقيقي. نسجّل الموضع لنعرف إن كان يجب
          // إعادة رفع الفيديو بـfaststart.
          let head = ''
          try {
            const h = await env.XLEARN.get(video.object_key,
              { range: { offset: 0, length: 256 } })
            if (h) {
              const b = new Uint8Array(await h.arrayBuffer())
              head = Array.from(b.subarray(0, 16),
                x => x.toString(16).padStart(2, '0')).join('')
              let off = 0, moov = 'unknown'
              for (let i = 0; i < 4 && off + 8 <= b.length; i++) {
                const sz = (b[off] << 24 | b[off + 1] << 16 |
                  b[off + 2] << 8 | b[off + 3]) >>> 0
                const ty = String.fromCharCode(
                  b[off + 4], b[off + 5], b[off + 6], b[off + 7])
                if (ty === 'moov') { moov = `front@${off}`; break }
                if (ty === 'mdat') { moov = 'end'; break }
                if (sz < 8) break
                off += sz
              }
              head += ` moov=${moov}`
            }
          } catch { /* التشخيص لا يُسقط البثّ */ }
          await logSecurity(env, request, 'learn_stream_serve',
            `video=${video.id} install=${installId.slice(0, 10)} size=${size} head=${head}`)
        }
        const span = size > 0 ? end - start + 1 : 0

        // كاش الحافة: البايتات نفسها تُخزَّن في أقرب نقطة Cloudflare
        // للمشاهد، فيصل أول إطار دون رحلة إلى R2 — وهذا هو الفارق بين
        // «تجهيز» طويل وبداية شبه فورية. الأمان لا يتغير: التحقق من الرمز
        // والاستحقاق يجري قبل قراءة الكاش، فالكاش يخزّن بايتات لا صلاحية،
        // ومن لا يحمل رمزاً صالحاً يُرفض قبل أن يُقرأ له بايت واحد.
        // مفتاح الكاش يتضمن حجم الملف: إعادة رفع الملف بنفس المفتاح يغيّر
        // الحجم فتتجدد النسخة بدل خدمة بايتات قديمة.
        const canon = new Request(
          `https://xapp-media.edge/${video.object_key}?z=${size}`)
        let base = await caches.default.match(canon)
        if (!base?.body) {
          const full = await env.XLEARN.get(video.object_key)
          if (!full?.body) throw new HttpError(404, 'ملف الفيديو مفقود')
          // tee يشقّ الجسم: نسخة تُكتب للكاش في الخلفية ونسخة تُخدم فوراً —
          // أول طلب لا ينتظر اكتمال التخزين.
          const [toCache, toServe] = full.body.tee()
          ctx.waitUntil(caches.default.put(canon, new Response(toCache, {
            headers: {
              'content-length': String(size),
              'cache-control': 'public, max-age=21600',
            },
          })))
          base = new Response(toServe)
        }
        const body = sliceStream(base.body!, start, span)

        const headers = new Headers({
          // النوع الأصلي صريحاً: `application/octet-stream` كان يجعل المشغّل
          // لا يعرف أنه مقطع فيرفض البدء. القيمة تكشف نوع الوسائط لا محتواها.
          'content-type': mime,
          // المشغّل يطلب قطعاً متتابعة، وهذا ما يجعله يستأنف من موضعه بلا
          // إعادة تنزيل ما شاهده. `no-store` كي لا يُخزَّن النصّ المخصّص.
          'accept-ranges': 'bytes',
          'cache-control': 'private, no-store'
        })
        if (size > 0) {
          headers.set('content-length', String(span))
          if (partial) headers.set('content-range', `bytes ${start}-${end}/${size}`)
        }
        return new Response(body, { status: partial ? 206 : 200, headers })
      }

      // غلاف الدورة. صورة عرض عامة بطبيعتها، لكنها تمرّ من هنا كي لا
      // يُكشف مفتاح R2 الخام لأي عميل.
      const coverMatch = path.match(/^\/v1\/learn\/cover\/([\w-]{1,64})$/)
      if (coverMatch && request.method === 'GET') {
        const c = await env.XDB
          .prepare('SELECT cover_key FROM x_courses WHERE id = ?1 AND published = 1')
          .bind(coverMatch[1]).first<{ cover_key: string }>()
        if (!c?.cover_key) throw new HttpError(404, 'لا غلاف')
        const obj = await env.XLEARN.get(c.cover_key)
        if (!obj?.body) throw new HttpError(404, 'not found')
        const headers = new Headers()
        obj.writeHttpMetadata(headers)
        headers.set('cache-control', 'public, max-age=86400')
        return new Response(obj.body, { headers })
      }

      // ---------- لوحة المالك ----------

      if (path.startsWith('/v1/owner/')) {
        // جلسة المالك تُتحقق بسرّها المستقل و`typ=owner`، لا بدور داخل جلسة
        // عادية. أي رمز آخر — ولو صحّ توقيعه — لا يفتح اللوحة.
        const ownerToken = request.headers.get('authorization')?.replace(/^Bearer\s+/i, '').trim() ?? ''
        let ownerPayload: Record<string, any>
        try {
          ownerPayload = await verifyOwnerJwt(env, ownerToken)
        } catch {
          await logSecurity(env, request, 'non_owner_admin_attempt', `path=${path}`)
          throw new HttpError(401, 'جلسة المالك غير صالحة')
        }
        if (ownerPayload.sub !== caller.uid) {
          await logSecurity(env, request, 'owner_session_uid_mismatch', `jwt=${ownerPayload.sub} caller=${caller.uid}`)
          throw new HttpError(401, 'جلسة المالك غير صالحة')
        }

        // كل ردود اللوحة مشفّرة بمفتاح مشتق من الجلسة نفسها. استجابة مسرّبة
        // (سجل وسيط، نسخة احتياطية، كاش) تبقى غير مقروءة بلا الجلسة.
        const sealed = async (payload: unknown) =>
          json({ enc: await ownerSeal(ownerToken, payload) }, 200, {
            'cache-control': 'no-store',
            'x-enc': 'aes-gcm'
          })

        if (path === '/v1/owner/overview' && request.method === 'GET') {
          const since = new Date(Date.now() - DAY).toISOString()
          const attacks = ATTACK_REASONS.map(() => '?').join(',')
          const [installs, users, pending, attacksToday, activeToday] = await Promise.all([
            // جهاز فريد: إعادة التثبيت أو تحديث النسخة لا تحتسب هاتفاً جديداً
            env.XDB.prepare(
              "SELECT COUNT(DISTINCT COALESCE(device_id, install_id)) c FROM x_installs"
            ).first<{ c: number }>(),
            env.XDB.prepare("SELECT COUNT(*) c FROM x_users WHERE role != 'owner'").first<{ c: number }>(),
            env.XDB.prepare("SELECT COUNT(*) c FROM x_requests WHERE status = 'pending'").first<{ c: number }>(),
            env.XDB.prepare(
              `SELECT COUNT(*) c FROM x_security WHERE at > ?1 AND reason IN (${attacks})`
            ).bind(since, ...ATTACK_REASONS).first<{ c: number }>(),
            env.XDB.prepare(
              "SELECT COUNT(DISTINCT COALESCE(device_id, install_id)) c FROM x_installs WHERE last_seen > ?1"
            ).bind(since).first<{ c: number }>()
          ])
          const byVersion = await env.XDB.prepare(
            `SELECT app_version v, COUNT(DISTINCT COALESCE(device_id, install_id)) c
             FROM x_installs GROUP BY app_version ORDER BY c DESC`
          ).all<{ v: string; c: number }>()
          return sealed({
            installs: installs?.c ?? 0,
            users: users?.c ?? 0,
            pendingRequests: pending?.c ?? 0,
            securityEvents24h: attacksToday?.c ?? 0,
            activeInstalls24h: activeToday?.c ?? 0,
            installsByVersion: byVersion.results ?? [],
            settings
          })
        }

        if (path === '/v1/owner/settings' && request.method === 'GET') {
          return sealed({ settings })
        }

        if (path === '/v1/owner/settings' && request.method === 'PUT') {
          const body = await request.json() as Partial<XSettings>
          const next: XSettings = {
            // المنحة اليومية الواحدة: تُطبَّق على الزوار والمسجّلين والمشتركين.
            // الحقلان القديمان يُشتقّان منها ويُحفظان بنفس القيمة كي لا تظن
            // نسخة قديمة من التطبيق أن المالك ألغى المنحة.
            dailyFreeQuota: Math.max(0, Math.min(1000, Math.floor(Number(body.dailyFreeQuota ?? settings.dailyFreeQuota) || 0))),
            guestFileQuota: 0,
            minVersion: Math.max(0, Number(body.minVersion ?? settings.minVersion) || 0),
            blockedVersions: Array.isArray(body.blockedVersions)
              ? body.blockedVersions.map(Number).filter(Number.isSafeInteger) : settings.blockedVersions,
            telegramLink: typeof body.telegramLink === 'string' && /^https?:\/\//.test(body.telegramLink)
              ? body.telegramLink.trim() : settings.telegramLink,
            schematicsLocked: body.schematicsLocked ?? settings.schematicsLocked,
            compatLocked: body.compatLocked ?? settings.compatLocked,
            compatSearchCost: Math.max(0, Math.min(1000, Math.floor(Number(body.compatSearchCost ?? settings.compatSearchCost) || 0))),
            schemFilePrice: Math.max(0, Math.min(1000, Math.floor(
              Number(body.schemFilePrice ?? settings.schemFilePrice) || 0))),
            dailyGiftAmount: Math.max(0, Math.min(1000, Math.floor(Number(body.dailyGiftAmount ?? settings.dailyGiftAmount) || 0))),
            installBonus: Math.max(0, Math.min(1000, Math.floor(Number(body.installBonus ?? settings.installBonus) || 0))),
            videosHidden: body.videosHidden ?? settings.videosHidden,
            videosHiddenMessage: typeof body.videosHiddenMessage === 'string'
              ? body.videosHiddenMessage.slice(0, 300) : settings.videosHiddenMessage,
            guestCompatQuota: 0,
            appLocked: body.appLocked ?? settings.appLocked,
            lockMessage: typeof body.lockMessage === 'string' ? body.lockMessage.slice(0, 300) : settings.lockMessage,
            updateMessage: typeof body.updateMessage === 'string' ? body.updateMessage.slice(0, 500) : settings.updateMessage,
            updateUrl: typeof body.updateUrl === 'string' && (!body.updateUrl || /^https?:\/\//.test(body.updateUrl))
              ? body.updateUrl.trim() : settings.updateUrl,
            updateImageUrl: typeof body.updateImageUrl === 'string' ? body.updateImageUrl.slice(0, 500) : settings.updateImageUrl,
            // باقات البطاقات — تحقق صارم: عدد بطاقات وصلاحية وسعر ووصف
            packages: Array.isArray(body.packages)
              ? body.packages
                  .map(p => ({
                    // بلا Math.max(1,...): كان يرفع الصفر إلى واحد فيمرّ من
                    // المرشّح أدناه باقةٌ بلا بطاقات.
                    cards: Math.min(1000000, Math.max(0, Math.floor(Number(p?.cards) || 0))),
                    price: String(p?.price ?? '').slice(0, 30),
                    days: Math.max(0, Math.min(3650, Math.floor(Number(p?.days) || 0))),
                    desc: String(p?.desc ?? '').slice(0, 120),
                  }))
                  .filter(p => p.cards > 0)
                  .slice(0, 20)
              : settings.packages,
            // سياسة الخصوصية: نص طويل، نحدّه بـ 8000 حرف ونحفظه كما هو.
            // لا نُجري أي تفسير HTML — التطبيق يعرضه نصاً خاماً.
            privacyPolicy: typeof body.privacyPolicy === 'string'
              ? body.privacyPolicy.slice(0, 8000) : settings.privacyPolicy,

            // ── الدردشة: كل حقل يُتحقق ويُحدّ، والمفقود يبقى على قيمته ──
            chatEnabled: body.chatEnabled ?? settings.chatEnabled,
            chatReadOnly: body.chatReadOnly ?? settings.chatReadOnly,
            chatTheme: ['classic', 'bubble', 'dark', 'neon'].includes(String(body.chatTheme))
              ? String(body.chatTheme) : settings.chatTheme,
            chatWelcome: typeof body.chatWelcome === 'string'
              ? body.chatWelcome.slice(0, 300) : settings.chatWelcome,
            chatMaxLength: Math.max(80, Math.min(4000,
              Math.floor(Number(body.chatMaxLength ?? settings.chatMaxLength) || 1000))),
            chatImagesEnabled: body.chatImagesEnabled ?? settings.chatImagesEnabled,
            chatWriteScope: ['all', 'registered', 'subscribers'].includes(String(body.chatWriteScope))
              ? String(body.chatWriteScope) : settings.chatWriteScope,
            chatMediaScope: ['subscribers', 'none'].includes(String(body.chatMediaScope))
              ? String(body.chatMediaScope) : settings.chatMediaScope,
            chatMaxMediaMb: Math.max(25, Math.min(200,
              Math.floor(Number(body.chatMaxMediaMb ?? settings.chatMaxMediaMb) || 200))),
            chatMediaSeconds: Math.max(5, Math.min(300,
              Math.floor(Number(body.chatMediaSeconds ?? settings.chatMediaSeconds) || 120))),
            chatPollMs: Math.max(2000, Math.min(30000,
              Math.floor(Number(body.chatPollMs ?? settings.chatPollMs) || 4000))),
            // الأقسام تُطبَّع بنفس منطق القراءة، فلا يكتب المالك قائمة
            // معرّفات مكررة أو فارغة تُربك الفرز لاحقاً.
            chatRooms: Array.isArray(body.chatRooms) ? normalizeSettings({
              ...DEFAULT_SETTINGS, chatRooms: body.chatRooms,
            }, { chatRooms: body.chatRooms }).chatRooms : settings.chatRooms,
          }
          await env.XDB.prepare(
            `INSERT INTO x_settings (id, data) VALUES ('main', ?1)
             ON CONFLICT(id) DO UPDATE SET data = ?1`
          ).bind(JSON.stringify(normalizeSettings(next, body))).run()
          return sealed({ ok: true, settings: next })
        }

        if (path === '/v1/owner/users' && request.method === 'GET') {
          const rows = await env.XDB.prepare(
            "SELECT id, username, display_name, role, active, device_id, expires_at, quota_balance, quota_expires_at, created_at FROM x_users WHERE role != 'guest' ORDER BY created_at DESC LIMIT 500"
          ).all()
          return sealed({ users: rows.results ?? [] })
        }

        // إنشاء حساب مفعّل مباشرة — المالك يضيف مشتركين بنفسه
        if (path === '/v1/owner/users' && request.method === 'POST') {
          const body = await request.json() as {
            username?: string; password?: string; displayName?: string
            days?: number; cards?: number; cardDays?: number
          }
          const username = body.username?.trim() ?? ''
          if (!/^[\w.\-@]{3,60}$/.test(username)) throw new HttpError(400, 'اسم مستخدم غير صالح')
          if ((body.password ?? '').length < 6) throw new HttpError(400, 'كلمة المرور قصيرة')
          if (await xUserByName(env.XDB, username)) throw new HttpError(409, 'اسم المستخدم مستخدم')
          const days = Math.max(0, Math.min(3650, Number(body.days) || 0))
          const cards = Math.max(0, Math.min(100000, Math.floor(Number(body.cards) || 0)))
          const cardDays = Math.max(0, Math.min(3650, Number(body.cardDays) || 0))
          await env.XDB.prepare(
            `INSERT INTO x_users (id, username, display_name, password_hash, role, active, device_id, expires_at, quota_balance, quota_expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, 'user', 1, NULL, ?5, ?6, ?7, ?8)`
          ).bind(
            `u_${uid()}`, username, body.displayName?.trim() ?? '',
            await hashPassword(body.password!),
            days > 0 ? Date.now() + days * DAY * 1000 : 0,
            cards,
            cardDays > 0 ? Date.now() + cardDays * DAY * 1000 : 0,
            new Date().toISOString()
          ).run()
          return sealed({ ok: true })
        }

        // محافظ الزوار: عملات يشتريها الزائر بلا حساب، مفتاحها معرّف الجهاز.
        if (path === '/v1/owner/wallets' && request.method === 'GET') {
          const rows = await env.XDB.prepare(
            `SELECT w.device_id, w.balance, w.expires_at, w.updated_at,
                    (SELECT app_version FROM x_installs i
                      WHERE i.device_id = w.device_id
                      ORDER BY last_seen DESC LIMIT 1) app_version,
                    (SELECT last_ip FROM x_installs i
                      WHERE i.device_id = w.device_id
                      ORDER BY last_seen DESC LIMIT 1) last_ip,
                    (SELECT last_seen FROM x_installs i
                      WHERE i.device_id = w.device_id
                      ORDER BY last_seen DESC LIMIT 1) last_seen,
                    (SELECT username FROM x_users u
                      WHERE u.device_id = w.device_id LIMIT 1) username,
                    (SELECT id FROM x_users u
                      WHERE u.device_id = w.device_id LIMIT 1) user_id
             FROM x_guest_wallets w ORDER BY w.updated_at DESC LIMIT 500`
          ).all()
          return sealed({ wallets: rows.results ?? [] })
        }

        // تعديل مباشر: تعيين الرصيد والصلاحية إلى قيم محددة (لا جمع).
        if (path === '/v1/owner/wallets' && request.method === 'PUT') {
          const body = await request.json() as {
            deviceId?: string; coins?: number; days?: number
          }
          const dev = body.deviceId?.trim() ?? ''
          if (!dev || dev.length > 100) throw new HttpError(400, 'معرّف الجهاز مطلوب')
          const coins = Math.max(0, Math.min(1000000, Math.floor(Number(body.coins) || 0)))
          const days = Math.max(0, Math.min(3650, Math.floor(Number(body.days) || 0)))
          const now = new Date().toISOString()
          const existing = await env.XDB.prepare(
            'SELECT device_id FROM x_guest_wallets WHERE device_id = ?1'
          ).bind(dev).first<{ device_id: string }>()
          if (!existing) throw new HttpError(404, 'المحفظة غير موجودة')
          await env.XDB.prepare(
            `UPDATE x_guest_wallets SET balance = ?2, expires_at = ?3, updated_at = ?4
             WHERE device_id = ?1`
          ).bind(dev, coins, days > 0 ? Date.now() + days * DAY * 1000 : 0, now).run()
          return sealed({ ok: true, deviceId: dev, coins, days })
        }

        // حذف محفظة بالكامل.
        const walletDelete = path.match(/^\/v1\/owner\/wallets\/(.+)$/)
        if (walletDelete && request.method === 'DELETE') {
          const dev = decodeURIComponent(walletDelete[1]).trim()
          if (!dev) throw new HttpError(400, 'معرّف الجهاز مطلوب')
          await env.XDB.prepare('DELETE FROM x_guest_wallets WHERE device_id = ?1').bind(dev).run()
          return sealed({ ok: true, deleted: dev })
        }

        // إنقاص أو إضافة بجرعة: جمع/طرح لا تعيين. الرصيد لا ينزل تحت الصفر.
        if (path === '/v1/owner/wallets/adjust' && request.method === 'POST') {
          const body = await request.json() as {
            deviceId?: string; delta?: number; days?: number
          }
          const dev = body.deviceId?.trim() ?? ''
          if (!dev || dev.length > 100) throw new HttpError(400, 'معرّف الجهاز مطلوب')
          const delta = Math.max(-1000000, Math.min(1000000, Math.floor(Number(body.delta) || 0)))
          if (delta === 0) throw new HttpError(400, 'قيمة التعديل مطلوبة')
          const days = Math.max(0, Math.min(3650, Math.floor(Number(body.days) || 0)))
          const now = new Date().toISOString()
          const existing = await env.XDB.prepare(
            'SELECT balance FROM x_guest_wallets WHERE device_id = ?1'
          ).bind(dev).first<{ balance: number }>()
          if (!existing) throw new HttpError(404, 'المحفظة غير موجودة')
          const current = Math.max(0, Number(existing.balance) || 0)
          const next = Math.max(0, current + delta)
          if (days > 0) {
            await env.XDB.prepare(
              `UPDATE x_guest_wallets SET balance = ?2, expires_at = ?3, updated_at = ?4
               WHERE device_id = ?1`
            ).bind(dev, next, Date.now() + days * DAY * 1000, now).run()
          } else {
            await env.XDB.prepare(
              `UPDATE x_guest_wallets SET balance = ?2, updated_at = ?3 WHERE device_id = ?1`
            ).bind(dev, next, now).run()
          }
          return sealed({ ok: true, deviceId: dev, before: current, after: next })
        }

        if (path === '/v1/owner/wallets' && request.method === 'POST') {
          const body = await request.json() as {
            deviceId?: string; coins?: number; days?: number
          }
          const dev = body.deviceId?.trim() ?? ''
          if (!dev || dev.length > 100) throw new HttpError(400, 'معرّف الجهاز مطلوب')
          const coins = Math.max(0, Math.min(1000000, Math.floor(Number(body.coins) || 0)))
          const days = Math.max(0, Math.min(3650, Math.floor(Number(body.days) || 0)))
          if (coins <= 0) throw new HttpError(400, 'عدد العملات مطلوب')
          const now = new Date().toISOString()
          // شحن تراكمي: إعادة الشحن تضيف للرصيد ولا تُصفّره.
          await env.XDB.prepare(
            `INSERT INTO x_guest_wallets (device_id, balance, expires_at, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(device_id) DO UPDATE SET
               balance = balance + ?2,
               expires_at = ?3,
               updated_at = ?4`
          ).bind(dev, coins, days > 0 ? Date.now() + days * DAY * 1000 : 0, now).run()
          return sealed({ ok: true })
        }

        // حظر الأجهزة: عرض/حظر/فك
        // القائمة تُثري كل حظر بتفاصيله: من هو صاحبه إن كان له حساب، ومعرّفه،
        // وعنوان IP الذي هاجم منه، وآخر نسخة/IP معروفة للجهاز، وسبب الحظر،
        // وسجل الهجمات المرتبط. الحظر بلا تفاصيل لا يفيد المالك في القرار.
        if (path === '/v1/owner/bans' && request.method === 'GET') {
          const rows = await env.XDB.prepare(
            'SELECT * FROM x_bans ORDER BY at DESC LIMIT 300'
          ).all<{ id: string; kind: string; reason: string; permanent: number; at: string }>()

          const bans = await Promise.all((rows.results ?? []).map(async b => {
            const isDevice = b.kind === 'device'
            const dev = isDevice ? b.id : null
            // الحساب المرتبط بالجهاز المحظور — بالمعرّف أو بالمعرّف المربوط
            const account = dev
              ? await env.XDB.prepare(
                  'SELECT id, username, display_name, role, active, device_id FROM x_users WHERE device_id = ?1 LIMIT 1'
                ).bind(dev).first<any>()
              : null
            // آخر ظهور للجهاز: يمنح المالك النسخة والعنوان الأخير
            const install = dev
              ? await env.XDB.prepare(
                  `SELECT app_version, last_ip, last_seen, first_seen FROM x_installs
                   WHERE device_id = ?1 ORDER BY last_seen DESC LIMIT 1`
                ).bind(dev).first<any>()
              : null
            // آخر الأحداث الأمنية: السبب الحقيقي للحظر (هجوم، عبث، تجاوز)
            const events = await env.XDB.prepare(
              `SELECT reason, detail, path, ip, device_id, at FROM x_security
               WHERE (device_id IS NOT NULL AND device_id = ?1)
                  OR (ip IS NOT NULL AND ip = ?2)
               ORDER BY at DESC LIMIT 10`
            ).bind(dev ?? '\u0000', isDevice ? '\u0000' : b.id).all<any>()
            const ips = [...new Set((events.results ?? []).map((e: any) => e.ip).filter(Boolean))]
            return {
              id: b.id,
              kind: b.kind,
              reason: b.reason,
              permanent: b.permanent,
              at: b.at,
              account: account ?? null,
              appVersion: install?.app_version ?? '',
              lastIp: install?.last_ip ?? (isDevice ? '' : b.id),
              lastSeen: install?.last_seen ?? '',
              firstSeen: install?.first_seen ?? '',
              ips,
              events: events.results ?? []
            }
          }))
          return sealed({ bans })
        }
        if (path === '/v1/owner/bans' && request.method === 'POST') {
          const body = await request.json() as {
            deviceId?: string; ip?: string; reason?: string
          }
          const reason = body.reason?.trim() || 'manual'
          const dev = body.deviceId?.trim() ?? ''
          const addr = body.ip?.trim() ?? ''
          if (!dev && !addr) throw new HttpError(400, 'deviceId أو ip مطلوب')
          if (dev.length > 100 || addr.length > 64) throw new HttpError(400, 'قيمة طويلة جداً')
          // لا تحظر نفسك: زر الحظر في تبويب الأمان يعرض جهاز المالك وعنوانه
          // أيضاً، ونقرة واحدة كانت تكفي لقفل التطبيق على المالك نفسه بلا
          // أي طريق للرجوع من داخل التطبيق.
          const selfDev = deviceOf(request)
          const selfAddr = ip(request)
          if (dev && selfDev && dev === selfDev) {
            throw new HttpError(400, 'لا يمكنك حظر جهازك الحالي')
          }
          if (addr && selfAddr !== 'unknown' && addr === selfAddr) {
            throw new HttpError(400, 'لا يمكنك حظر عنوانك الحالي')
          }
          if (dev) await banDevice(env, dev, reason, request)
          if (addr) await banIp(env, addr, reason, request)
          return sealed({ ok: true })
        }
        const unban = path.match(/^\/v1\/owner\/bans\/(.+)$/)
        if (unban && request.method === 'DELETE') {
          const target = decodeURIComponent(unban[1])
          // الهدف قد يكون جهازاً أو عنوان IP — ننظّف المفتاحين معاً.
          await Promise.all([
            env.QUOTA.delete(`devban:${target}`),
            env.QUOTA.delete(`hardban:${target}`)
          ])
          await env.XDB.prepare('DELETE FROM x_bans WHERE id = ?1').bind(target).run()
          return sealed({ ok: true })
        }

        const userAction = path.match(/^\/v1\/owner\/users\/([\w-]+)\/(activate|deactivate|reset-device|delete|extend|quota)$/)
        if (userAction && request.method === 'POST') {
          const [, targetId, action] = userAction
          const target = await xUser(env.XDB, targetId)
          if (!target) throw new HttpError(404, 'user not found')
          if (target.role === 'owner') throw new HttpError(400, 'cannot modify owner')
          if (action === 'activate') {
            await env.XDB.prepare('UPDATE x_users SET active = 1 WHERE id = ?1').bind(targetId).run()
            await env.XDB.prepare("UPDATE x_requests SET status = 'approved' WHERE username = ?1 AND status = 'pending'").bind(target.username).run()
          } else if (action === 'deactivate') {
            await env.XDB.prepare('UPDATE x_users SET active = 0 WHERE id = ?1').bind(targetId).run()
          } else if (action === 'reset-device') {
            await env.XDB.prepare('UPDATE x_users SET device_id = NULL WHERE id = ?1').bind(targetId).run()
          } else if (action === 'extend') {
            const body = await request.json() as { days?: number }
            const days = Math.max(1, Math.min(3650, Number(body.days) || 30))
            await env.XDB.prepare('UPDATE x_users SET expires_at = ?1 WHERE id = ?2')
              .bind(Date.now() + days * DAY * 1000, targetId).run()
          } else if (action === 'quota') {
            // شحن بطاقات: يضيف للرصيد ويحدد صلاحية جديدة — كل الحسابات في السيرفر فقط
            const body = await request.json() as { cards?: number; days?: number }
            const cards = Math.max(0, Math.min(100000, Math.floor(Number(body.cards) || 0)))
            const days = Math.max(0, Math.min(3650, Number(body.days) || 0))
            if (cards <= 0) throw new HttpError(400, 'عدد البطاقات مطلوب')
            await env.XDB.prepare(
              `UPDATE x_users SET
                 quota_balance = quota_balance + ?2,
                 quota_expires_at = ?3
               WHERE id = ?1`
            ).bind(targetId, cards, days > 0 ? Date.now() + days * DAY * 1000 : 0).run()
          } else if (action === 'delete') {
            await env.XDB.prepare('DELETE FROM x_users WHERE id = ?1').bind(targetId).run()
          }
          return sealed({ ok: true })
        }

        if (path === '/v1/owner/requests' && request.method === 'GET') {
          const rows = await env.XDB.prepare(
            "SELECT * FROM x_requests ORDER BY created_at DESC LIMIT 200"
          ).all()
          return sealed({ requests: rows.results ?? [] })
        }

        const reqAction = path.match(/^\/v1\/owner\/requests\/([\w-]+)\/(approve|reject)$/)
        if (reqAction && request.method === 'POST') {
          const [, reqId, action] = reqAction
          const req = await env.XDB.prepare('SELECT * FROM x_requests WHERE id = ?1').bind(reqId).first<{ username: string }>()
          if (!req) throw new HttpError(404, 'request not found')
          const status = action === 'approve' ? 'approved' : 'rejected'
          await env.XDB.batch([
            env.XDB.prepare('UPDATE x_requests SET status = ?1 WHERE id = ?2').bind(status, reqId),
            ...(action === 'approve'
              ? [env.XDB.prepare('UPDATE x_users SET active = 1 WHERE username = ?1').bind(req.username)]
              : [])
          ])
          return sealed({ ok: true })
        }

        // سجل الأمان: المشبوه افتراضياً، والكل عند طلبه صراحة.
        // العرض الافتراضي يقتصر على ما يستحق نظرة المالك — هجوم أو تزوير أو
        // عبث — لا كل حدث روتيني. `all=1` يكشف السجل الكامل عند الحاجة.
        if (path === '/v1/owner/security' && request.method === 'GET') {
          const all = url.searchParams.get('all') === '1'
          const marks = SUSPICIOUS_REASONS.map(() => '?').join(',')
          const rows = all
            ? await env.XDB.prepare('SELECT * FROM x_security ORDER BY at DESC LIMIT 300').all()
            : await env.XDB.prepare(
                `SELECT * FROM x_security WHERE reason IN (${marks}) ORDER BY at DESC LIMIT 300`
              ).bind(...SUSPICIOUS_REASONS).all()
          // ملخّص بالنوع يمنح المالك صورة سريعة قبل التفاصيل.
          const byReason = await env.XDB.prepare(
            `SELECT reason, COUNT(*) c, MAX(at) last FROM x_security
             WHERE reason IN (${marks}) GROUP BY reason ORDER BY c DESC`
          ).bind(...SUSPICIOUS_REASONS).all()
          return sealed({
            events: rows.results ?? [],
            attacksOnly: !all,
            summary: byReason.results ?? []
          })
        }

        // حذف سجلات الأمان: الكل، أو نوع واحد، أو ما قبل تاريخ.
        // السجل ينمو بلا حد عملياً، وتركه للقارئ وحده يجعله عديم الفائدة.
        // محميّ بنفس بوابة جلسة المالك لكل مسارات /v1/owner/*.
        if (path === '/v1/owner/security' && request.method === 'DELETE') {
          const reason = url.searchParams.get('reason')?.trim() ?? ''
          const before = Number(url.searchParams.get('before')) || 0
          let deleted = 0
          if (reason) {
            const r = await env.XDB.prepare(
              'DELETE FROM x_security WHERE reason = ?1'
            ).bind(reason).run()
            deleted = Number(r.meta?.changes ?? 0)
          } else if (before > 0) {
            const r = await env.XDB.prepare(
              'DELETE FROM x_security WHERE at < ?1'
            ).bind(new Date(before).toISOString()).run()
            deleted = Number(r.meta?.changes ?? 0)
          } else {
            const r = await env.XDB.prepare('DELETE FROM x_security').run()
            deleted = Number(r.meta?.changes ?? 0)
          }
          await logSecurity(env, request, 'security_logs_cleared')
          return sealed({ ok: true, deleted })
        }

        if (path === '/v1/owner/announcements' && request.method === 'GET') {
          const rows = await env.XDB.prepare('SELECT id, data FROM x_announcements ORDER BY id DESC LIMIT 100').all<{ id: string; data: string }>()
          return sealed({
            announcements: (rows.results ?? []).map(r => ({ id: r.id, ...JSON.parse(r.data) }))
          })
        }

        // إنشاء إعلان — يقبل صورة base64 تُرفع لـ bucket الخاص بـ X
        if (path === '/v1/owner/announcements' && request.method === 'POST') {
          const body = await request.json() as {
            title?: string; subtitle?: string; linkUrl?: string; imageUrl?: string
            imageB64?: string; imageExt?: string
          }
          if (!body.title?.trim()) throw new HttpError(400, 'title required')
          const id = `xann_${uid()}`
          let imageUrl = body.imageUrl?.trim() ?? ''
          if (body.imageB64) {
            const ext = (body.imageExt ?? 'png').replace(/[^\w]/g, '').slice(0, 5) || 'png'
            const bytes = Uint8Array.from(atob(body.imageB64), c => c.charCodeAt(0))
            if (bytes.length > 4 * 1024 * 1024) throw new HttpError(413, 'الصورة كبيرة (أقصى 4MB)')
            const key = `ads/${id}.${ext}`
            const mime = EXT_MIME[ext] ?? 'image/png'
            await env.XMEDIA.put(key, bytes, { httpMetadata: { contentType: mime } })
            imageUrl = `/v1/media/${key}`
          }
          await env.XDB.prepare(
            'INSERT INTO x_announcements (id, data) VALUES (?1, ?2)'
          ).bind(id, JSON.stringify({
            title: body.title.trim(), subtitle: body.subtitle?.trim() ?? '',
            linkUrl: body.linkUrl?.trim() ?? '', imageUrl,
            active: true, order: Date.now(), createdAt: new Date().toISOString()
          })).run()
          // الإعلان يهمّ كل مستخدمي التطبيق، فهو الدفع الوحيد العام.
          // بلا انتظار: نشر الإعلان يجب أن يعود فوراً ولو حمّل الإرسال ثواني.
          ctx.waitUntil(pushToAll(env, {
            title: body.title.trim(),
            body: body.subtitle?.trim() || 'إعلان جديد من PhoneX',
            target: { k: 'ad' },
          }).catch(() => 0))
          return sealed({ ok: true, id, imageUrl, pushed: pushEnabled(env) })
        }

        const annDelete = path.match(/^\/v1\/owner\/announcements\/([\w-]+)$/)
        if (annDelete && request.method === 'DELETE') {
          await env.XDB.prepare('DELETE FROM x_announcements WHERE id = ?1').bind(annDelete[1]).run()
          return sealed({ ok: true })
        }

        // ---------- إشراف المالك على الدردشة ----------

        // آخر الرسائل في كل قسم — للمراجعة والحذف.
        if (path === '/v1/owner/chat/messages' && request.method === 'GET') {
          const roomId = url.searchParams.get('room') ?? ''
          const rows = roomId
            ? await env.XDB.prepare(
                `SELECT id, room_id, user_id, kind, body, media_key, media_mime,
                        media_size, created_at, deleted
                 FROM x_chat_messages WHERE room_id = ?1
                 ORDER BY created_at DESC LIMIT 100`
              ).bind(roomId).all<any>()
            : await env.XDB.prepare(
                `SELECT id, room_id, user_id, kind, body, media_key, media_mime,
                        media_size, created_at, deleted
                 FROM x_chat_messages ORDER BY created_at DESC LIMIT 100`
              ).all<any>()
          const list = rows.results ?? []
          const profiles = await chatProfiles(env.XDB, list.map(m => m.user_id))
          const users = new Map<string, string>()
          if (list.length) {
            const ids = [...new Set(list.map(m => m.user_id))]
            const ph = ids.map((_, i) => `?${i + 1}`).join(',')
            const ur = await env.XDB.prepare(
              `SELECT id, username, display_name FROM x_users WHERE id IN (${ph})`
            ).bind(...ids).all<{ id: string; username: string; display_name: string }>()
            for (const u of ur.results ?? []) users.set(u.id, u.display_name || u.username)
          }
          return sealed({
            messages: list.map(m => ({
              id: m.id, roomId: m.room_id, kind: m.kind, body: m.body,
              mediaUrl: m.media_key ? `/v1/media/${m.media_key}` : '',
              mediaMime: m.media_mime, mediaSize: m.media_size,
              at: m.created_at, deleted: !!m.deleted,
              userId: m.user_id,
              username: users.get(m.user_id) ?? '',
              nickname: profiles.get(m.user_id)?.nickname ?? '',
              avatarUrl: profiles.get(m.user_id)?.avatar_key
                ? `/v1/media/${profiles.get(m.user_id)!.avatar_key}` : '',
            })),
          })
        }

        // حذف رسالة: ناعم، فلا يفقد الحوار سياقه ويبقى الأثر للمالك.
        const chatMsgDelete = path.match(/^\/v1\/owner\/chat\/messages\/([\w-]+)$/)
        if (chatMsgDelete && request.method === 'DELETE') {
          await env.XDB.prepare(
            'UPDATE x_chat_messages SET deleted = 1 WHERE id = ?1'
          ).bind(chatMsgDelete[1]).run()
          await logSecurity(env, request, 'owner_chat_delete', `msg=${chatMsgDelete[1]}`)
          return sealed({ ok: true })
        }

        // حذف كل رسائل قسم — يستخدمه المالك عند تنظيف قسم من الفوضى.
        if (path === '/v1/owner/chat/purge' && request.method === 'POST') {
          const body = await request.json<{ room?: string }>().catch(() => ({} as { room?: string }))
          const roomId = String(body.room ?? '')
          if (!roomId) throw new HttpError(400, 'room required')
          await env.XDB.prepare(
            'UPDATE x_chat_messages SET deleted = 1 WHERE room_id = ?1'
          ).bind(roomId).run()
          await logSecurity(env, request, 'owner_chat_purge', `room=${roomId}`)
          return sealed({ ok: true })
        }

        // كتم/طرد: room فارغ = كل الأقسام. الكتم بلا نهاية (until=0)،
        // والطرد بمدة محددة لأن الطرد الدائم بلا سبب يقطع المستخدم عن
        // المجتمع كلياً — والمالك يستطيع تكراره إن لزم.
        if (path === '/v1/owner/chat/action' && request.method === 'POST') {
          const body = await request.json<{
            userId?: string; kind?: string; room?: string
            reason?: string; minutes?: number
          }>().catch(() => ({} as {
            userId?: string; kind?: string; room?: string
            reason?: string; minutes?: number
          }))
          const userId = String(body.userId ?? '')
          const kind = String(body.kind ?? '')
          if (!userId || !['mute', 'kick'].includes(kind)) {
            throw new HttpError(400, 'userId و kind (mute|kick) مطلوبان')
          }
          const roomId = String(body.room ?? '')
          if (roomId && !settings.chatRooms.some(r => r.id === roomId)) {
            throw new HttpError(404, 'القسم غير موجود')
          }
          const target = await xUser(env.XDB, userId)
          if (!target) throw new HttpError(404, 'المستخدم غير موجود')
          if (target.role === 'owner') throw new HttpError(400, 'لا يمكن تقييد المالك')

          // minutes = 0 تعني «دائم» للنوعين. الطرد الدائم قد يبدو حظراً،
          // لكنه يبقى داخل الدردشة وحدها ولا يمس دخول التطبيق.
          const minutes = Math.max(0, Math.min(43200, Math.floor(Number(body.minutes) || 0)))
          const until = minutes > 0 ? Date.now() + minutes * 60000 : 0
          const id = `cact_${uid()}`
          await env.XDB.prepare(
            `INSERT INTO x_chat_actions (id, user_id, kind, room_id, reason, until, at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`
          ).bind(
            id, userId, kind, roomId,
            cleanText(body.reason, 120), until, new Date().toISOString()
          ).run()
          await logSecurity(env, request, `owner_chat_${kind}`,
            `user=${userId} room=${roomId || 'all'} until=${until}`)
          return sealed({ ok: true, id, until })
        }

        // رفع التقييد عن مستخدم.
        if (path === '/v1/owner/chat/action/clear' && request.method === 'POST') {
          const body = await request.json<{
            userId?: string; kind?: string
          }>().catch(() => ({} as { userId?: string; kind?: string }))
          const userId = String(body.userId ?? '')
          if (!userId) throw new HttpError(400, 'userId required')
          const kind = String(body.kind ?? '')
          if (kind && ['mute', 'kick'].includes(kind)) {
            await env.XDB.prepare(
              'DELETE FROM x_chat_actions WHERE user_id = ?1 AND kind = ?2'
            ).bind(userId, kind).run()
          } else {
            await env.XDB.prepare(
              'DELETE FROM x_chat_actions WHERE user_id = ?1'
            ).bind(userId).run()
          }
          await logSecurity(env, request, 'owner_chat_clear', `user=${userId} kind=${kind || 'all'}`)
          return sealed({ ok: true })
        }

        // قائمة المكتومين والمطرودين — لمتابعة من أوقفه المالك.
        if (path === '/v1/owner/chat/actions' && request.method === 'GET') {
          const rows = await env.XDB.prepare(
            `SELECT id, user_id, kind, room_id, reason, until, at
             FROM x_chat_actions ORDER BY at DESC LIMIT 200`
          ).all<any>()
          const list = rows.results ?? []
          const ids = [...new Set(list.map(r => r.user_id))]
          const names = new Map<string, string>()
          if (ids.length) {
            const ph = ids.map((_, i) => `?${i + 1}`).join(',')
            const ur = await env.XDB.prepare(
              `SELECT id, username, display_name FROM x_users WHERE id IN (${ph})`
            ).bind(...ids).all<{ id: string; username: string; display_name: string }>()
            for (const u of ur.results ?? []) names.set(u.id, u.display_name || u.username)
          }
          const now = Date.now()
          return sealed({
            actions: list.map(r => ({
              id: r.id, userId: r.user_id, kind: r.kind, roomId: r.room_id,
              reason: r.reason, until: r.until, at: r.at,
              username: names.get(r.user_id) ?? '',
              // منتهي = لا يزال الصف لكن أثره زال. until === 0 يعني بلا نهاية.
              active: r.until === 0 || r.until > now,
            })),
          })
        }

        // ---------- إدارة الدورات (للمالك) ----------
        //
        // كل ردود هذا القسم تمرّ من sealed() كبقية اللوحة، فلا تُقرأ بلا
        // جلسة المالك. الكود الصريح يُعاد مرة واحدة عند التوليد — وبعدها
        // لا يوجد صريحاً في أي مكان، ولو ضاع فالمالك يولّد غيره.

        if (path === '/v1/owner/learn/courses' && request.method === 'GET') {
          const courses = await env.XDB.prepare(
            `SELECT id, title, subtitle, description, cover_key, locked, sort, published, created_at
             FROM x_courses ORDER BY sort, created_at DESC`
          ).all<any>()
          // object_key مطلوب هنا: اللوحة تُرسله مع كل تعديل وصفّي، وبلا
          // إعادته كان تعديل العنوان أو القفل يرسل مفتاحاً فارغاً فيرفضه
          // الخادم — «مفتاح مطلوب» على عملية لا تخصّ المفتاح أصلاً.
          const videos = await env.XDB.prepare(
            `SELECT id, course_id, title, description, mode, sort, duration_s, size_bytes, published, object_key
             FROM x_course_videos ORDER BY sort, created_at`
          ).all<any>()
          const keys = await env.XDB.prepare(
            `SELECT id, course_id, label, max_uses, used_count, device_id, expires_at, revoked, created_at
             FROM x_course_keys ORDER BY created_at DESC LIMIT 500`
          ).all<any>()
          // يُعرض المعرّفان: install_id هو ما يُسحب فعلاً، وdevice_id
          // للعرض فقط لأن المالك يتعرّف على أجهزته به. لو عرضنا device_id
          // وحده لصار زر السحب بلا أثر — فهو لا يحكم المنحة.
          const grants = await env.XDB.prepare(
            `SELECT install_id, device_id, course_id, key_id, user_id, at
             FROM x_course_grants ORDER BY at DESC LIMIT 500`
          ).all<any>()

          const byCourse = new Map<string, any[]>()
          for (const v of videos.results ?? []) {
            const l = byCourse.get(v.course_id) ?? []
            l.push(v)
            byCourse.set(v.course_id, l)
          }
          const keysByCourse = new Map<string, number>()
          const activeByCourse = new Map<string, number>()
          for (const k of keys.results ?? []) {
            keysByCourse.set(k.course_id, (keysByCourse.get(k.course_id) ?? 0) + 1)
            if (!k.revoked) {
              activeByCourse.set(k.course_id, (activeByCourse.get(k.course_id) ?? 0) + 1)
            }
          }
          const subsByCourse = new Map<string, number>()
          for (const g of grants.results ?? []) {
            subsByCourse.set(g.course_id, (subsByCourse.get(g.course_id) ?? 0) + 1)
          }
          const titleOf = new Map<string, string>()
          for (const c of courses.results ?? []) titleOf.set(c.id, c.title)

          return sealed({
            courses: (courses.results ?? []).map(c => ({
              id: c.id, title: c.title, subtitle: c.subtitle,
              description: c.description, coverKey: c.cover_key,
              // رابط الغلاف الجاهز للعرض في اللوحة (موقّع كما بقية الصور).
              coverUrl: c.cover_key ? `/v1/learn/cover/${c.id}` : '',
              locked: !!c.locked, sort: c.sort, published: !!c.published,
              createdAt: c.created_at,
              videoCount: (byCourse.get(c.id) ?? []).length,
              keyCount: keysByCourse.get(c.id) ?? 0,
              activeKeyCount: activeByCourse.get(c.id) ?? 0,
              subscriberCount: subsByCourse.get(c.id) ?? 0,
              videos: (byCourse.get(c.id) ?? []).map(v => ({
                id: v.id, title: v.title, description: v.description,
                mode: v.mode, sort: v.sort, durationS: v.duration_s,
                sizeBytes: v.size_bytes, published: !!v.published,
                objectKey: v.object_key,
                // روابط الصور تُعاد للمالك ليرى غلافه ومصغّراته ويستبدلها من
                // اللوحة مباشرة. بلا هذه الحقول كانت اللوحة عمياء عن الصور
                // التي رفعها، فلا يعرف المالك أين رفعها ولا كيف تبدو.
                thumbUrl: v.thumb_key ? `/v1/learn/thumb/${v.id}` : '',
              })),
            })),
            keys: (keys.results ?? []).map(k => ({
              id: k.id, courseId: k.course_id, courseTitle: titleOf.get(k.course_id) ?? '',
              label: k.label, maxUses: k.max_uses, usedCount: k.used_count,
              deviceId: k.device_id ? `${k.device_id.slice(0, 8)}…` : '',
              expiresAt: k.expires_at, revoked: !!k.revoked, createdAt: k.created_at,
            })),
            subscribers: (grants.results ?? []).map(g => ({
              // installId هو ما يُسحب به فعلاً؛ deviceId للعرض فقط لأن
              // المالك يتعرّف على أجهزته به.
              installId: g.install_id, deviceId: g.device_id,
              shortId: `${(g.device_id || g.install_id || '').slice(0, 8)}…`,
              courseId: g.course_id, courseTitle: titleOf.get(g.course_id) ?? '',
              keyId: g.key_id, userId: g.user_id, at: g.at,
            })),
          })
        }

        // إنشاء/تعديل دورة
        if (path === '/v1/owner/learn/course' && request.method === 'POST') {
          const b = await request.json<any>().catch(() => ({}))
          const id = String(b.id ?? '').trim() || `c_${Date.now().toString(36)}`
          if (!/^[\w-]{1,64}$/.test(id)) throw new HttpError(400, 'معرّف غير صالح')
          const now = new Date().toISOString()
          const existing = await env.XDB
            .prepare('SELECT id FROM x_courses WHERE id = ?1').bind(id).first()
          const vals = {
            title: String(b.title ?? '').slice(0, 200) || 'دورة بلا عنوان',
            subtitle: String(b.subtitle ?? '').slice(0, 200),
            description: String(b.description ?? '').slice(0, 4000),
            cover: String(b.coverKey ?? '').slice(0, 200),
            locked: b.locked === false ? 0 : 1,
            sort: Number.isFinite(Number(b.sort)) ? Math.floor(Number(b.sort)) : 0,
            published: b.published === false ? 0 : 1,
          }
          if (existing) {
            await env.XDB.prepare(
              `UPDATE x_courses SET title=?1, subtitle=?2, description=?3, cover_key=?4,
               locked=?5, sort=?6, published=?7, updated_at=?8 WHERE id=?9`
            ).bind(vals.title, vals.subtitle, vals.description, vals.cover,
                   vals.locked, vals.sort, vals.published, now, id).run()
          } else {
            await env.XDB.prepare(
              `INSERT INTO x_courses (id, title, subtitle, description, cover_key, locked, sort, published, created_at, updated_at)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)`
            ).bind(id, vals.title, vals.subtitle, vals.description, vals.cover,
                   vals.locked, vals.sort, vals.published, now).run()
          }
          await logSecurity(env, request, 'owner_learn_course', `id=${id}`)
          return sealed({ ok: true, id })
        }

        // حذف دورة مع فيديوهاتها ومفاتيحها ومنحها
        const courseDel = path.match(/^\/v1\/owner\/learn\/course\/([\w-]{1,64})$/)
        if (courseDel && request.method === 'DELETE') {
          const id = courseDel[1]
          await env.XDB.batch([
            env.XDB.prepare('DELETE FROM x_course_videos WHERE course_id = ?1').bind(id),
            env.XDB.prepare('DELETE FROM x_course_keys WHERE course_id = ?1').bind(id),
            env.XDB.prepare('DELETE FROM x_course_grants WHERE course_id = ?1').bind(id),
            env.XDB.prepare('DELETE FROM x_courses WHERE id = ?1').bind(id),
          ])
          await logSecurity(env, request, 'owner_learn_course_delete', `id=${id}`)
          return sealed({ ok: true })
        }

        // إضافة/تعديل فيديو. body.objectKey هو المفتاح داخل دلو XLEARN.
        if (path === '/v1/owner/learn/video' && request.method === 'POST') {
          const b = await request.json<any>().catch(() => ({}))
          const courseId = String(b.courseId ?? '')
          const objKey = String(b.objectKey ?? '').trim()
          if (!/^[\w-]{1,64}$/.test(courseId)) throw new HttpError(400, 'courseId مطلوب')
          if (objKey.includes('..')) throw new HttpError(400, 'objectKey غير صالح')
          const course = await env.XDB
            .prepare('SELECT id FROM x_courses WHERE id = ?1').bind(courseId).first()
          if (!course) throw new HttpError(404, 'الدورة غير موجودة')
          const id = String(b.id ?? '').trim() || `v_${Date.now().toString(36)}`
          const now = new Date().toISOString()
          const mode = b.mode === 'free' ? 'free' : 'locked'
          const vals = {
            title: String(b.title ?? '').slice(0, 200) || 'فيديو',
            description: String(b.description ?? '').slice(0, 2000),
            mime: String(b.mime ?? 'video/mp4').slice(0, 60),
            duration: Math.max(0, Math.floor(Number(b.durationS) || 0)),
            size: Math.max(0, Math.floor(Number(b.sizeBytes) || 0)),
            sort: Number.isFinite(Number(b.sort)) ? Math.floor(Number(b.sort)) : 0,
            published: b.published === false ? 0 : 1,
          }
          const exists = await env.XDB
            .prepare('SELECT id FROM x_course_videos WHERE id = ?1').bind(id).first()
          if (exists) {
            // كائن R2 لا يُلمس في التعديل: الوصف والقفل لا علاقة لهما بالملف.
            // تمرير مفتاح فارغ كان يمحو الرابط الأصلي فيصير الفيديو بلا ملف.
            await env.XDB.prepare(
              `UPDATE x_course_videos SET course_id=?1, title=?2, description=?3,
               object_key=COALESCE(NULLIF(?4,''), object_key),
               mime=?5, duration_s=?6, size_bytes=?7, mode=?8, sort=?9, published=?10 WHERE id=?11`
            ).bind(courseId, vals.title, vals.description, objKey, vals.mime,
                   vals.duration, vals.size, mode, vals.sort, vals.published, id).run()
          } else {
            if (!objKey) throw new HttpError(400, 'objectKey مطلوب لفيديو جديد')
            await env.XDB.prepare(
              `INSERT INTO x_course_videos (id, course_id, title, description, object_key, mime,
               duration_s, size_bytes, mode, sort, published, created_at)
               VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)`
            ).bind(id, courseId, vals.title, vals.description, objKey, vals.mime,
                   vals.duration, vals.size, mode, vals.sort, vals.published, now).run()
          }
          await logSecurity(env, request, 'owner_learn_video', `id=${id} course=${courseId}`)
          return sealed({ ok: true, id })
        }

        const videoDel = path.match(/^\/v1\/owner\/learn\/video\/([\w-]{1,64})$/)
        if (videoDel && request.method === 'DELETE') {
          await env.XDB.prepare('DELETE FROM x_course_videos WHERE id = ?1')
            .bind(videoDel[1]).run()
          await logSecurity(env, request, 'owner_learn_video_delete', `id=${videoDel[1]}`)
          return sealed({ ok: true })
        }

        // ---------- تحرير التوافقات (للمالك) ----------
        //
        // السجلات تأتي من المرآة للقراءة فقط ولا تُمسّ. كل تحرير يُحفظ في
        // `x_compat_edits` كطبقة فوقها: `patch` تعديل سجل قائم، `new` سجل
        // جديد كتبه المالك، `cat` صفة/نوع فرعي. الحذف لا يمسح المصدر أيضاً —
        // يُعلَّم `deleted` فيُخفى من نتائج البحث ويبقى قابلاً للاسترجاع.
        //
        // القائمة تعرض السجل بعد تطبيق التعديلات، فيرى المالك ما يراه
        // المستخدم لا الصفّ الخام.

        /** يطبّق تعديلات المالك على سجل مصدر واحد. */
        const applyEdit = (
          docKey: string, fields: Record<string, unknown>,
          edits: Map<string, any>
        ): Record<string, unknown> | null => {
          const e = edits.get(docKey)
          if (!e || e.deleted) return e?.deleted ? null : fields
          try {
            const patch = JSON.parse(e.data) as Record<string, unknown>
            return { ...fields, ...patch }
          } catch {
            return fields
          }
        }

        // بحث داخل سجلات شركة — للمالك بلا خصم ولا حدود بحث ضيّقة، لأن
        // اللوحة تحتاج أن ترى الشركة كاملة لتختار منها ما تعدّله.
        if (path === '/v1/owner/compat/list' && request.method === 'GET') {
          const url = new URL(request.url)
          const brand = (url.searchParams.get('brand') ?? '').trim().slice(0, 80)
          const q = (url.searchParams.get('q') ?? '').trim().slice(0, 48).toLowerCase()
          const type = (url.searchParams.get('type') ?? '').trim().slice(0, 24).toUpperCase()
          if (!brand) throw new HttpError(400, 'brand required')

          // السجلات الخام من المرآة لهذه الشركة (أو صيغة `v_` الافتراضية).
          let brandFile = brand
          let keyword: string | undefined
          if (brand.startsWith('v_')) {
            const vb = VIRTUAL_SUB_BRANDS.find(v => `v_${v.key}` === brand)
            brandFile = vb?.file ?? brand
            keyword = vb?.key
          }

          const res = await mirrorSearchCompat(env.MIRROR, {
            query: q || ' ', brandFile, keyword,
            type: type || undefined, limit: 200
          })
          const edits = await compatEditsFor(env, brandFile)
          const records: any[] = []
          for (const d of res) {
            const merged = applyEdit(d.id, d.fields, edits)
            // مفتاح الوثيقة بعد الدمج: `id` داخل حقول الصفّ رقمي داخلي،
            // وطمسه لمفتاح الوثيقة هو سبب «الصفّ غير موجود» عند الحفظ.
            if (merged) records.push({ ...merged, id: d.id, edited: edits.has(d.id) })
          }
          // السجلات الجديدة التي كتبها المالك لهذه الشركة: ليست في المرآة
          // أصلاً، فبلا إضافتها هنا لا يراها المالك بعد إنشائها.
          const newRows = await env.XDB.prepare(
            `SELECT doc_key, data FROM x_compat_edits
             WHERE brand_file = ?1 AND kind = 'new' AND deleted = 0`
          ).bind(brandFile).all<any>()
          for (const r of newRows.results ?? []) {
            try {
              records.push({ ...JSON.parse(r.data), id: r.doc_key, edited: true, isNew: true })
            } catch { /* صفّ تالف لا يُسقط القائمة */ }
          }

          const types = await cached(env, `ctypes:${brandFile}`, 3600,
            () => compatTypesOf(env.MIRROR, brandFile))
          // الأنواع التي أضافها المالك تُضمّ إلى المعروض أيضاً.
          const catRows = await env.XDB.prepare(
            `SELECT data FROM x_compat_edits WHERE brand_file = ?1 AND kind = 'cat' AND deleted = 0`
          ).bind(brandFile).all<any>()
          const catTypes: string[] = []
          for (const r of catRows.results ?? []) {
            try {
              const t = String(JSON.parse(r.data)?.name ?? '').toUpperCase()
              if (t && !types.includes(t) && !catTypes.includes(t)) catTypes.push(t)
            } catch { /* تجاهل */ }
          }
          return sealed({
            records,
            types: [...types, ...catTypes],
            knownTypes: [...COMPAT_TYPES, ...catTypes],
            brand: brandFile
          })
        }

        // إنشاء/تعديل وعمليات على صفوف التوافقات — بحسب `op`.
        //
        // كتابة واحدة موحّدة بدل مسارات متعدّدة: العمليات الأربع (تعديل صف،
        // حذف صف، إضافة صفوف، حذف صف جديد) كلها تغيير على طبقة واحدة، ومسار
        // واحد يبقى مفهوماً ومُدقّقاً.
        if (path === '/v1/owner/compat/edit' && request.method === 'POST') {
          const body = await request.json<any>().catch(() => ({}))
          const op = String(body.op ?? '').trim()
          const brandRef = String(body.brand ?? '').trim().slice(0, 80)
          // صيغة `v_*` تُحوَّل إلى ملف الشركة الأم كما في مسارات القراءة؛ بلا
          // هذا كان التحرير يُكتب على اسم الشركة الافتراضية بينما البحث يقرأ
          // الملف الحقيقي، فلا يرى أحد التعديل.
          let brandFile = brandRef
          if (brandRef.startsWith('v_')) {
            const vb = VIRTUAL_SUB_BRANDS.find(v => `v_${v.key}` === brandRef)
            if (!vb) throw new HttpError(400, 'شركة افتراضية غير معروفة')
            brandFile = vb.file
          }
          const now = new Date().toISOString()

          const put = async (docKey: string, kind: string, data: unknown, deleted: boolean) =>
            env.XDB.prepare(
              `INSERT INTO x_compat_edits (id, doc_key, brand_file, kind, data, deleted, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
               ON CONFLICT(id) DO UPDATE SET
                 data = ?5, deleted = ?6, updated_at = ?7, brand_file = ?3, kind = ?4`
            ).bind(`ce_${docKey}_${kind}`, docKey, brandFile, kind,
                   JSON.stringify(data), deleted ? 1 : 0, now).run()

          if (op === 'patch') {
            const id = String(body.id ?? '').trim()
            const fields = body.fields
            if (!id || !fields || typeof fields !== 'object' || Array.isArray(fields)) {
              throw new HttpError(400, 'id و fields مطلوبان')
            }
            // الطبقة تُبنى على أي تعديل سابق لنفس الصفّ: صفّ أنشأه المالك
            // (`new`) أو تعديل سابق على صفّ المرآة (`patch`). حصر البحث في
            // `new` كان يجعل تعديل صفّ المرآة يُبنى على أساس فارغ، فيُستبدل
            // الصفّ بدل أن يُدمج ويضيع الحقل المحفوظ قبله — والإضافة على صفّ
            // جديد تنجح لأن مسارها `new`، فيبدو الفشل خاصاً بالصفوف القائمة.
            const prev = await env.XDB.prepare(
              `SELECT data, kind FROM x_compat_edits
               WHERE doc_key = ?1 AND brand_file = ?2 AND kind IN ('new', 'patch')`
            ).bind(id, brandFile).first<{ data: string; kind: string }>()
            let merged: Record<string, unknown> = {}
            if (prev) { try { merged = JSON.parse(prev.data) } catch { /* تجاهل */ } }
            const original = prev?.kind === 'new' ? null : await env.MIRROR.prepare(
              "SELECT data FROM docs WHERE id = ?1 AND brand_file = ?2 AND collection = 'compatibility'"
            ).bind(id, brandFile).first<{ data: string }>()
            if (!original && prev?.kind !== 'new') throw new HttpError(404, 'صف التوافق غير موجود في هذه الشركة')
            // كل حقل يُفلتَر باسمه: لا يُقبل مفتاح لم نختره، ولا قيمة بلا حدّ.
            // كان `fields` يُدمج كما وصل، فجلسة مسروقة تكتب ما تشاء في الصفّ
            // الذي يقرأه كل المستخدمين.
            const safe: Record<string, unknown> = {}
            for (const key of Object.keys(fields as Record<string, unknown>)) {
              const v = (fields as Record<string, unknown>)[key]
              if (key === 'compatibleModels') {
                if (Array.isArray(v) && (v.length > COMPAT_MAX_MODELS ||
                    v.some(m => typeof m !== 'string' || m.length > COMPAT_MAX_MODEL_LEN))) {
                  throw new HttpError(400, 'عدد النصوص أو طول أحدها يتجاوز الحد المسموح')
                }
                const list = sanitizeModels(Array.isArray(v) ? v : splitModelLines(v))
                if (!list.length) throw new HttpError(400, 'لا موديلات صالحة في الصفّ')
                safe.compatibleModels = list
              } else if (key === 'componentType') {
                safe.componentType = await assertCompatType(env, brandFile, String(v))
              } else if (key === 'subCategory') {
                const name = String((v as any)?.name ?? '').trim().slice(0, COMPAT_MAX_SUB_LEN)
                safe.subCategory = { name }
              } else if (key === 'note') {
                safe.note = String(v ?? '').trim().slice(0, COMPAT_MAX_NOTE_LEN)
              }
              // أي مفتاح آخر يُهمَل بصمت — لا يصل إلى قاعدة البيانات.
            }
            merged = { ...merged, ...safe }
            // صفّ أنشأه المالك يبقى `new` حتى لا ينقلب حذفه وهمياً في مصدر
            // لا وجود له فيه؛ وما عداه `patch` على صفّ المرآة.
            const kind = prev?.kind === 'new' ? 'new' : 'patch'
            await put(id, kind, merged, false)
            const saved = await env.XDB.prepare(
              'SELECT data FROM x_compat_edits WHERE id = ?1 AND brand_file = ?2'
            ).bind(`ce_${id}_${kind}`, brandFile).first<{ data: string }>()
            if (!saved) throw new HttpError(500, 'تعذر تأكيد حفظ الصف')
            await logSecurity(env, request, 'owner_compat_patch', `id=${id} brand=${brandFile}`)
            return sealed({ ok: true, id, kind, record: {
              ...(original ? JSON.parse(original.data) : {}), ...JSON.parse(saved.data), id,
            } })
          }

          if (op === 'delete') {
            const id = String(body.id ?? '').trim()
            if (!id) throw new HttpError(400, 'id مطلوب')
            // صف أنشأه المالك يُحذف فعلياً: لا مصدر تحته ليُعلَّم عليه.
            const isNew = await env.XDB.prepare(
              `SELECT 1 x FROM x_compat_edits WHERE doc_key = ?1 AND brand_file = ?2 AND kind = 'new'`
            ).bind(id, brandFile).first<any>()
            if (isNew) {
              await env.XDB.prepare('DELETE FROM x_compat_edits WHERE doc_key = ?1 AND brand_file = ?2')
                .bind(id, brandFile).run()
            } else {
              // الحذف لا يمسح الطبقة: يُعلَّم `deleted` فوق محتواها القائم
              // ليبقى قابلاً للاسترجاع. البحث بـ`kind='patch'` وحده كان
              // يُسقط التعديل قبل الحذف (صفّ مُعدَّل سابقاً) فيُمحى ما كتبه
              // المالك، وهو السلوك الذي يظهر كـ«الحذف لا ينجح» على صفّ قائم.
              const prev = await env.XDB.prepare(
                `SELECT data FROM x_compat_edits
                 WHERE doc_key = ?1 AND brand_file = ?2 AND kind IN ('patch', 'new')`
              ).bind(id, brandFile).first<{ data: string }>()
              const original = await env.MIRROR.prepare(
                "SELECT id FROM docs WHERE id = ?1 AND brand_file = ?2 AND collection = 'compatibility'"
              ).bind(id, brandFile).first()
              if (!original) throw new HttpError(404, 'صف التوافق غير موجود في هذه الشركة')
              await put(id, 'patch', prev ? JSON.parse(prev.data) : {}, true)
            }
            await logSecurity(env, request, 'owner_compat_delete', `id=${id} brand=${brandFile}`)
            return sealed({ ok: true, id })
          }

          if (op === 'restore') {
            const id = String(body.id ?? '').trim()
            if (!id) throw new HttpError(400, 'id مطلوب')
            const prev = await env.XDB.prepare(
              'SELECT data, kind FROM x_compat_edits WHERE doc_key = ?1'
            ).bind(id).first<{ data: string; kind: string }>()
            if (!prev) throw new HttpError(404, 'لا تعديل لهذا الصف')
            await put(id, prev.kind, JSON.parse(prev.data), false)
            await logSecurity(env, request, 'owner_compat_restore', `id=${id}`)
            return sealed({ ok: true, id })
          }

          if (op === 'add') {
            // صفوف متعدّدة في نداء واحد: المالك يكتب صفّين تحت بعضهما كما
            // يكتب قائمة، والنداء الواحد يجعل الإضافة إمّا كلها أو لا شيء.
            const rows = Array.isArray(body.rows) ? body.rows : []
            if (!rows.length) throw new HttpError(400, 'rows مطلوبة')
            if (rows.length > 50) throw new HttpError(400, 'الحد 50 صفاً في المرة')
            const made: string[] = []
            for (const raw of rows) {
              const r = raw as Record<string, unknown>
              const models = Array.isArray(r.compatibleModels)
                ? sanitizeModels(r.compatibleModels)
                : splitModelLines(r.compatibleModels)
              // النوع يُتحقق منه مقابل الأنواع المعروفة ومنها ما أضافه المالك،
              // وكان قبلها يُقبل أي نصّ فيُخزَّن نوع لا وجود له.
              const kind = await assertCompatType(env, brandFile, String(r.componentType ?? ''))
              const sub = String(r.subCategory ?? '').trim().slice(0, COMPAT_MAX_SUB_LEN)
              if (!models.length) throw new HttpError(400, 'لا موديلات في أحد الصفوف')
              const id = `new_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36).slice(-4)}`
              await put(id, 'new', {
                compatibleModels: models,
                componentType: kind,
                subCategory: { name: sub || kind },
                note: String(r.note ?? '').trim().slice(0, COMPAT_MAX_NOTE_LEN),
              }, false)
              made.push(id)
            }
            await logSecurity(env, request, 'owner_compat_add',
              `brand=${brandFile} n=${made.length}`)
            return sealed({ ok: true, ids: made })
          }

          if (op === 'addType') {
            const name = String(body.name ?? '').trim().slice(0, 24).toUpperCase()
            if (!name) throw new HttpError(400, 'اسم النوع مطلوب')
            await put(`type_${name}`, 'cat', { name }, false)
            await logSecurity(env, request, 'owner_compat_addtype', `type=${name}`)
            return sealed({ ok: true, name })
          }

          throw new HttpError(400, 'عملية غير معروفة')
        }

        // ملفات الشركات المتاحة للتحرير — مصدرها المرآة نفسها التي يبحث
        // فيها المستخدمون، فلا تُعرض على المالك شركة لا أثر لها.
        if (path === '/v1/owner/compat/brands' && request.method === 'GET') {
          const files = await compatBrandFiles(env.MIRROR)
          const added = await env.XDB.prepare(
            `SELECT DISTINCT brand_file f FROM x_compat_edits
             WHERE brand_file <> '' AND deleted = 0`
          ).all<{ f: string }>()
          const set = new Set(files)
          for (const r of added.results ?? []) set.add(r.f)
          return sealed({
            brands: [...set].sort(),
            subBrands: VIRTUAL_SUB_BRANDS.map(v => ({ key: v.key, name: v.name, file: v.file })),
            types: [...COMPAT_TYPES]
          })
        }
// ── الرفع المُجزَّأ للفيديوهات الكبيرة ──
        //
        // لماذا: Cloudflare يرد 413 على أي طلب يتجاوز 100MB على حافة الشبكة
        // قبل أن ينفّذ الـWorker سطراً واحداً. لذلك المقطع يتقسّم إلى أجزاء
        // كل جزء طلب مستقل صغير. R2 يجمعها في كائن واحد عند الإكمال.
        // وهذا يعطي أيضاً استكمالاً بعد انقطاع الشبكة: الأجزاء المرفوعة تبقى.

        // بدء جلسة رفع. يعيد uploadId ومفتاح الكائن.
        if (path === '/v1/owner/learn/upload/init' && request.method === 'POST') {
          await rateLimit(env, request, 'owner_upload', 60, 3600)
          const b = await request.json<any>().catch(() => ({}))
          const courseId = String(b.courseId ?? '')
          if (!/^[\w-]{1,64}$/.test(courseId)) throw new HttpError(400, 'courseId مطلوب')
          const course = await env.XDB
            .prepare('SELECT id FROM x_courses WHERE id = ?1').bind(courseId).first()
          if (!course) throw new HttpError(404, 'الدورة غير موجودة')

          const extMatch = String(b.name ?? '').toLowerCase().match(/\.(mp4|m4v|mov|webm|mkv)$/)
          const ext = extMatch ? extMatch[1] : 'mp4'
          const mime = (String(b.mime ?? 'video/mp4')).slice(0, 60)
          const objectKey = `courses/${courseId}/${Date.now().toString(36)}.${ext}`

          // إنشاء رفع R2 متعدّد الأجزاء: نحتفظ بـuploadId لإرسال الأجزاء لاحقاً.
          const mp = await env.XLEARN.createMultipartUpload(objectKey, {
            httpMetadata: { contentType: mime },
          })
          const id = `u_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`
          await env.XDB.prepare(
            `INSERT INTO x_course_uploads (id, course_id, object_key, r2_upload_id, title,
             description, mode, mime, size_bytes, parts_done, owner_id, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,0,?10,?11)`
          ).bind(id, courseId, objectKey, mp.uploadId,
                 String(b.title ?? '').slice(0, 200) || 'فيديو',
                 String(b.description ?? '').slice(0, 2000),
                 b.mode === 'free' ? 'free' : 'locked', mime,
                 Math.max(0, Math.floor(Number(b.size) || 0)),
                 caller.uid, new Date().toISOString()).run()
          return sealed({ ok: true, uploadId: id, objectKey })
        }

        // رفع جزء واحد. رقم الجزء يبدأ من 1 كما في R2.
        const upPart = path.match(/^\/v1\/owner\/learn\/upload\/(u_[\w]+)\/part\/(\d{1,5})$/)
        if (upPart && request.method === 'PUT') {
          await rateLimit(env, request, 'owner_upload_part', 400, 3600)
          const upload = await env.XDB
            .prepare('SELECT * FROM x_course_uploads WHERE id = ?1').bind(upPart[1])
            .first<any>()
          if (!upload) throw new HttpError(404, 'جلسة الرفع غير موجودة')
          // جلسة المالك وحده: لا يكمل رفعاً بدأه غيره.
          if (upload.owner_id && upload.owner_id !== caller.uid) {
            throw new HttpError(403, 'جلسة رفع تخصّ مالكاً آخر')
          }
          const partNo = Number(upPart[2])
          if (partNo < 1 || partNo > 10000) throw new HttpError(400, 'رقم الجزء غير صالح')
          if (!request.body) throw new HttpError(400, 'لا يوجد جزء')

          const mp = env.XLEARN.resumeMultipartUpload(upload.object_key, upload.r2_upload_id)
          // R2 يرد رمزاً (etag) لكل جزء، ولا بد من إعادته للعميل كي يرسله
          // مرتّباً عند الإكمال — الجمع يفشل بلا هذه الرموز.
          const uploaded = await mp.uploadPart(partNo, request.body)
          await env.XDB.prepare(
            'UPDATE x_course_uploads SET parts_done = MAX(parts_done, ?1) WHERE id = ?2'
          ).bind(partNo, upPart[1]).run()
          return sealed({ ok: true, part: partNo, etag: uploaded.etag })
        }

        // إكمال الجلسة: R2 يجمع الأجزاء ثم نسجّل الفيديو في جدول الدورات.
        if (path === '/v1/owner/learn/upload/complete' && request.method === 'POST') {
          await rateLimit(env, request, 'owner_upload', 60, 3600)
          const b = await request.json<any>().catch(() => ({}))
          const upId = String(b.uploadId ?? '')
          const upload = await env.XDB
            .prepare('SELECT * FROM x_course_uploads WHERE id = ?1').bind(upId).first<any>()
          if (!upload) throw new HttpError(404, 'جلسة الرفع غير موجودة')
          if (upload.owner_id && upload.owner_id !== caller.uid) {
            throw new HttpError(403, 'جلسة رفع تخصّ مالكاً آخر')
          }
          // الأجزاء يجب أن تُرسل مرتّبة، وإلا فشل الجمع برسالة غامضة من R2.
          const parts = Array.isArray(b.parts)
            ? b.parts.map((p: any) => ({ partNumber: Number(p.partNumber), etag: String(p.etag) }))
                .filter((p: any) => p.partNumber >= 1 && p.etag)
                .sort((a: any, c: any) => a.partNumber - c.partNumber)
            : []
          if (!parts.length) throw new HttpError(400, 'لا توجد أجزاء للإكمال')

          const mp = env.XLEARN.resumeMultipartUpload(upload.object_key, upload.r2_upload_id)
          const obj = await mp.complete(parts)
          const size = (obj as any)?.size ?? upload.size_bytes

          const id = `v_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 5)}`
          const sortRow = await env.XDB
            .prepare('SELECT COALESCE(MAX(sort), 0) + 1 AS next FROM x_course_videos WHERE course_id = ?1')
            .bind(upload.course_id).first<{ next: number }>()
          await env.XDB.prepare(
            `INSERT INTO x_course_videos (id, course_id, title, description, object_key, mime,
             duration_s, size_bytes, mode, sort, published, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,0,?7,?8,?9,1,?10)`
          ).bind(id, upload.course_id, upload.title, upload.description, upload.object_key,
                 upload.mime, size, upload.mode, sortRow?.next ?? 1,
                 new Date().toISOString()).run()
          await env.XDB.prepare('DELETE FROM x_course_uploads WHERE id = ?1').bind(upId).run()
          await logSecurity(env, request, 'owner_learn_upload',
            `id=${id} course=${upload.course_id} bytes=${size} parts=${parts.length} chunked`)
          return sealed({ ok: true, id, objectKey: upload.object_key, size })
        }

        // إلغاء جلسة: يُبرَم الرفع في R2 كي لا تبقى أجزاء معلّقة بلا كائن.
        if (path === '/v1/owner/learn/upload/abort' && request.method === 'POST') {
          await rateLimit(env, request, 'owner_upload', 60, 3600)
          const b = await request.json<any>().catch(() => ({}))
          const upId = String(b.uploadId ?? '')
          const upload = await env.XDB
            .prepare('SELECT * FROM x_course_uploads WHERE id = ?1').bind(upId).first<any>()
          if (!upload) return sealed({ ok: true, skipped: true })
          if (upload.owner_id && upload.owner_id !== caller.uid) {
            throw new HttpError(403, 'جلسة رفع تخصّ مالكاً آخر')
          }
          try {
            const mp = env.XLEARN.resumeMultipartUpload(upload.object_key, upload.r2_upload_id)
            await mp.abort()
          } catch { /* الرفع قد يكون أُكمل أو أُبطل سابقاً — لا نُفشل الطلب */ }
          await env.XDB.prepare('DELETE FROM x_course_uploads WHERE id = ?1').bind(upId).run()
          return sealed({ ok: true })
        }

        // رفع ملف فيديو مباشرة إلى دلو الدورات.
        //
        // الجسم يُدفق إلى R2 بلا تحويل base64: فيديو 200MB كان يصير 270MB
        // نصاً ويُقرأ كاملاً في الذاكرة، وهذا يُنهي العامل. هنا لا يمرّ من
        // الذاكرة إلا ما يحتاجه الدفق.
        //
        // العنوان: /v1/owner/learn/upload?courseId=..&title=..&mode=..&name=..
        // والجسم هو بايتات الملف كما هي.
        if (path === '/v1/owner/learn/upload' && request.method === 'POST') {
          // حدّ رفع مستقل: جلسة مالك مسروقة لا يجب أن تملأ الدلو بلا سقف.
          await rateLimit(env, request, 'owner_upload', 30, 3600)
          const courseId = url.searchParams.get('courseId') ?? ''
          if (!/^[\w-]{1,64}$/.test(courseId)) throw new HttpError(400, 'courseId مطلوب')
          const course = await env.XDB
            .prepare('SELECT id FROM x_courses WHERE id = ?1').bind(courseId).first()
          if (!course) throw new HttpError(404, 'الدورة غير موجودة')

          const title = (url.searchParams.get('title') ?? '').slice(0, 200) || 'فيديو'
          const desc = (url.searchParams.get('description') ?? '').slice(0, 2000)
          const mode = url.searchParams.get('mode') === 'free' ? 'free' : 'locked'
          const mime = (request.headers.get('content-type') || 'video/mp4').slice(0, 60)
          // الجسم الخام فقط: multipart يحمل حدوداً بين الأجزاء تُحفظ داخل
          // الملف فيفسد التشغيل. الرفض هنا يمنع تلفاً صامتاً في الدلو.
          if (mime.includes('multipart/')) {
            throw new HttpError(400, 'أرسل الملف كجسم خام لا multipart')
          }

          // امتداد الملف من الاسم الأصلي، ونتحقق من كونه امتداداً معروفاً:
          // لا نثق باسم يرسله العميل كما هو.
          const rawName = url.searchParams.get('name') ?? ''
          const extMatch = rawName.toLowerCase().match(/\.(mp4|m4v|mov|webm|mkv)$/)
          const ext = extMatch ? extMatch[1] : 'mp4'

          const declared = Number(request.headers.get('content-length') || 0)
          // 95MB لا 350MB: Cloudflare يرد 413 على أي طلب يتجاوز 100MB على
          // حافة الشبكة قبل وصوله إلى الـWorker، فحدّ أعلى من ذلك وهم لا
          // يُبلَغ. الملفات الأكبر تمرّ عبر مسارات الرفع المُجزَّأ أعلاه.
          const MAX_UPLOAD = 95 * 1024 * 1024
          if (declared > MAX_UPLOAD) {
            throw new HttpError(413, 'الملف أكبر من 95MB — استخدم الرفع المُجزَّأ')
          }
          if (!request.body) throw new HttpError(400, 'لا يوجد ملف')

          const objectKey = `courses/${courseId}/${Date.now().toString(36)}.${ext}`
          await env.XLEARN.put(objectKey, request.body, {
            httpMetadata: { contentType: mime },
          })

          const head = await env.XLEARN.head(objectKey)
          const size = head?.size ?? declared

          const id = `v_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 5)}`
          const sortRow = await env.XDB
            .prepare('SELECT COALESCE(MAX(sort), 0) + 1 AS next FROM x_course_videos WHERE course_id = ?1')
            .bind(courseId).first<{ next: number }>()
          await env.XDB.prepare(
            `INSERT INTO x_course_videos (id, course_id, title, description, object_key, mime,
             duration_s, size_bytes, mode, sort, published, created_at)
             VALUES (?1,?2,?3,?4,?5,?6,0,?7,?8,?9,1,?10)`
          ).bind(id, courseId, title, desc, objectKey, mime, size, mode,
                 sortRow?.next ?? 1, new Date().toISOString()).run()
          await logSecurity(env, request, 'owner_learn_upload',
            `id=${id} course=${courseId} bytes=${size}`)
          return sealed({ ok: true, id, objectKey, size })
        }

        // توليد كود لدورة واحدة. يُعاد صريحاً مرة واحدة هنا فقط.
        if (path === '/v1/owner/learn/key' && request.method === 'POST') {
          const b = await request.json<any>().catch(() => ({}))
          const courseId = String(b.courseId ?? '')
          const course = await env.XDB
            .prepare('SELECT id, title FROM x_courses WHERE id = ?1')
            .bind(courseId).first<{ id: string; title: string }>()
          if (!course) throw new HttpError(404, 'الدورة غير موجودة')
          const maxUses = Math.max(1, Math.min(1000, Math.floor(Number(b.maxUses) || 1)))
          const days = Math.max(0, Math.min(3650, Math.floor(Number(b.days) || 0)))
          const expires = days > 0 ? Date.now() + days * DAY : 0
          const code = makeKeyCode()
          const id = `k_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`
          await env.XDB.prepare(
            `INSERT INTO x_course_keys (id, course_id, code_hash, label, max_uses, used_count,
             device_id, expires_at, revoked, created_at, used_at)
             VALUES (?1,?2,?3,?4,?5,0,'',?6,0,?7,'')`
          ).bind(id, courseId, await keyHash(code), String(b.label ?? '').slice(0, 100),
                 maxUses, expires, new Date().toISOString()).run()
          await logSecurity(env, request, 'owner_learn_key', `course=${courseId} key=${id}`)
          // الكود الصريح في هذا الرد وحده — غير محفوظ في أي جدول.
          return sealed({ ok: true, id, code, courseId, courseTitle: course.title, maxUses, expiresAt: expires })
        }

        // إلغاء كود (revoke) — يمنع استخدامه من الآن، ويمنح المشتركين
        // الحاليين خيار السحب إن أراد المالك (انظر grants).
        const keyRevoke = path.match(/^\/v1\/owner\/learn\/key\/([\w-]{1,64})$/)
        if (keyRevoke && request.method === 'DELETE') {
          await env.XDB.prepare('UPDATE x_course_keys SET revoked = 1 WHERE id = ?1')
            .bind(keyRevoke[1]).run()
          await logSecurity(env, request, 'owner_learn_key_revoke', `key=${keyRevoke[1]}`)
          return sealed({ ok: true })
        }

        // سحب التمكين من مشترك: يحذف المنحة فيموت وصوله فوراً بلا حاجة
        // لتغيير أي شيء في جهازه، ولو كان الفيديو محمّلاً عنده.
        if (path === '/v1/owner/learn/revoke' && request.method === 'POST') {
          const b = await request.json<any>().catch(() => ({}))
          // يُقبل installId، وdeviceId احتياطاً للنسخ القديمة من اللوحة:
          // حذف بمعرّف لا يحكم المنحة كان يُبلّغ بنجاح بلا حذف شيء، فيظنّ
          // المالك أنه سحب الوصول والوصول باقٍ.
          const installId = String(b.installId ?? '').trim()
          const deviceId = String(b.deviceId ?? '').trim()
          const courseId = String(b.courseId ?? '').trim()
          if ((!installId && !deviceId) || !courseId) {
            throw new HttpError(400, 'installId و courseId مطلوبان')
          }
          if (installId) {
            await env.XDB.prepare(
              'DELETE FROM x_course_grants WHERE install_id = ?1 AND course_id = ?2'
            ).bind(installId, courseId).run()
          } else {
            await env.XDB.prepare(
              'DELETE FROM x_course_grants WHERE device_id = ?1 AND course_id = ?2'
            ).bind(deviceId, courseId).run()
          }
          await logSecurity(env, request, 'owner_learn_revoke',
            `install=${installId || '-'} dev=${deviceId || '-'} course=${courseId}`)
          return sealed({ ok: true })
        }

        // رفع غلاف الدورة — نفس نمط رفع وسائط الإعلانات.
        if (path === '/v1/owner/learn/cover' && request.method === 'POST') {
          const body = await request.json<any>().catch(() => ({}))
          const courseId = String(body.courseId ?? '')
          if (!/^[\w-]{1,64}$/.test(courseId)) throw new HttpError(400, 'courseId مطلوب')
          const dataB64 = String(body.dataB64 ?? '')
          if (dataB64.length > 8_000_000) throw new HttpError(413, 'الصورة كبيرة')
          const bytes = b64d(dataB64)
          if (!bytes.length) throw new HttpError(400, 'لا بيانات')
          const mime = String(body.mime ?? 'image/jpeg').slice(0, 60)
          const ext = mime.includes('png') ? 'png' : mime.includes('webp') ? 'webp' : 'jpg'
          const key = `learn/covers/${courseId}.${ext}`
          await env.XLEARN.put(key, bytes, { httpMetadata: { contentType: mime } })
          await env.XDB.prepare(
            'UPDATE x_courses SET cover_key = ?1, updated_at = ?2 WHERE id = ?3'
          ).bind(key, new Date().toISOString(), courseId).run()
          await logSecurity(env, request, 'owner_learn_cover', `course=${courseId}`)
          return sealed({ ok: true, coverKey: key })
        }

        // مصغّرة الفيديو. تُرفع مستقلة عن الفيديو كي يستطيع المالك استبدالها
        // دون إعادة رفع المقطع، وتُربط بمعرّف الفيديو لا بالدورة.
        if (path === '/v1/owner/learn/thumb' && request.method === 'POST') {
          const body = await request.json<any>().catch(() => ({}))
          const videoId = String(body.videoId ?? '')
          if (!/^[\w-]{1,64}$/.test(videoId)) throw new HttpError(400, 'videoId مطلوب')
          const dataB64 = String(body.dataB64 ?? '')
          if (dataB64.length > 8_000_000) throw new HttpError(413, 'الصورة كبيرة')
          const bytes = b64d(dataB64)
          if (!bytes.length) throw new HttpError(400, 'لا بيانات')
          const mime = String(body.mime ?? 'image/jpeg').slice(0, 60)
          const ext = mime.includes('png') ? 'png' : mime.includes('webp') ? 'webp' : 'jpg'
          const key = `learn/thumbs/${videoId}.${ext}`
          await env.XLEARN.put(key, bytes, { httpMetadata: { contentType: mime } })
          await env.XDB.prepare(
            'UPDATE x_course_videos SET thumb_key = ?1 WHERE id = ?2'
          ).bind(key, videoId).run()
          await logSecurity(env, request, 'owner_learn_thumb', `video=${videoId}`)
          return sealed({ ok: true, thumbKey: key })
        }
      }

      throw new HttpError(404, 'not found')
    } catch (err) {
      if (err instanceof HttpError) {
        return json({ ok: false, error: err.message, status: err.status }, err.status)
      }
      // خطأ غير متوقّع يُسجَّل مع نصّه. كان يُبتلع ويُعاد «server error»
      // بلا أثر، فيستحيل على المالك معرفة سبب عطل يراه المستخدم.
      await logSecurity(env, request, 'server_error',
        err instanceof Error ? `${err.name}: ${err.message}` : String(err))
      return json({ ok: false, error: 'server error' }, 500)
    }
  }
}
