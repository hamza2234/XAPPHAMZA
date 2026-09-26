-- x-app-db — قاعدة بيانات تطبيق X الخاصة (معزولة تماماً عن phonex-mirror)
-- لا تُكتب أي بيانات هنا إلا من worker التطبيق x-app-api

CREATE TABLE IF NOT EXISTS x_users (
  id            TEXT PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  display_name  TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL DEFAULT '',
  role          TEXT NOT NULL DEFAULT 'user',   -- owner | user | guest
  active        INTEGER NOT NULL DEFAULT 0,     -- الحسابات الجديدة تنتظر تفعيل المالك
  device_id     TEXT,
  expires_at    INTEGER NOT NULL DEFAULT 0,     -- 0 = بلا انتهاء
  quota_balance INTEGER NOT NULL DEFAULT 0,     -- رصيد بطاقات عرض المخططات
  quota_expires_at INTEGER NOT NULL DEFAULT 0,  -- انتهاء صلاحية البطاقات (0 = بلا انتهاء)
  created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS x_users_role ON x_users (role, active);

CREATE TABLE IF NOT EXISTS x_requests (
  id          TEXT PRIMARY KEY,
  username    TEXT NOT NULL,
  note        TEXT NOT NULL DEFAULT '',
  device_id   TEXT,
  status      TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS x_installs (
  install_id  TEXT PRIMARY KEY,
  device_id   TEXT,
  app_version TEXT NOT NULL DEFAULT 'unknown',
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  last_ip     TEXT
);
CREATE INDEX IF NOT EXISTS x_installs_seen ON x_installs (last_seen);

CREATE TABLE IF NOT EXISTS x_settings (
  id   TEXT PRIMARY KEY,
  data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS x_announcements (
  id   TEXT PRIMARY KEY,
  data TEXT NOT NULL
);

-- حظر دائم (جهاز أو IP) — مستقل عن تغيير العنوان
CREATE TABLE IF NOT EXISTS x_bans (
  id        TEXT PRIMARY KEY,   -- device_id أو ip
  kind      TEXT NOT NULL,      -- device | ip
  reason    TEXT NOT NULL DEFAULT '',
  permanent INTEGER NOT NULL DEFAULT 1,
  at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS x_security (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT,
  ip        TEXT,
  path      TEXT,
  reason    TEXT NOT NULL,
  detail    TEXT NOT NULL DEFAULT '',
  at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS x_security_at ON x_security (at);

-- ══════════════════════════════════════════════════════════════
-- الدردشة المجتمعية (مجموعة واحدة بأقسام) — لا رسائل خاصة بين الأفراد
-- ══════════════════════════════════════════════════════════════

-- ملفات تعريف الدردشة: كنية وصورة شخصية، منفصلة عن بيانات الحساب الرسمية
-- كي لا يغيّر المستخدم اسم حسابه من داخل الدردشة.
-- notify: كتم الإشعارات من جهة المستخدم نفسه (0 = مكتوم).
CREATE TABLE IF NOT EXISTS x_chat_profiles (
  user_id    TEXT PRIMARY KEY,
  nickname   TEXT NOT NULL DEFAULT '',
  avatar_key TEXT NOT NULL DEFAULT '',
  notify     INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
);

-- آخر رسالة شاهدها كل مستخدم في كل قسم — أساس «من رأى الرسالة».
-- نحفظ ختماً زمنياً لا قائمة معرّفات: استعلام واحد صغير لكل قسم يكفي
-- لعرض صور المشاهدين، بدل صف لكل (مستخدم × رسالة).
CREATE TABLE IF NOT EXISTS x_chat_seen (
  user_id   TEXT NOT NULL,
  room_id   TEXT NOT NULL,
  last_at   INTEGER NOT NULL DEFAULT 0,
  seen_at   TEXT NOT NULL,
  PRIMARY KEY (user_id, room_id)
);
CREATE INDEX IF NOT EXISTS x_chat_seen_room ON x_chat_seen (room_id, last_at DESC);

-- الرسائل. room_id يفصل الأقسام، وkind يميّز النص عن الوسائط أو الرسائل
-- النظامية. الحذف ناعم (deleted) ليبقى الأثر للمالك ولا يفقد الحوار سياقه.
CREATE TABLE IF NOT EXISTS x_chat_messages (
  id         TEXT PRIMARY KEY,
  room_id    TEXT NOT NULL,
  user_id    TEXT NOT NULL,
  kind       TEXT NOT NULL DEFAULT 'text',   -- text | image | audio | video | system
  body       TEXT NOT NULL DEFAULT '',
  media_key  TEXT NOT NULL DEFAULT '',
  media_mime TEXT NOT NULL DEFAULT '',
  media_size INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  deleted    INTEGER NOT NULL DEFAULT 0,
  -- مخطط الموجة ومدة الصوت/الفيديو (أُضيفا لاحقاً بـALTER على القواعد القائمة).
  waveform   TEXT NOT NULL DEFAULT '',
  media_seconds INTEGER NOT NULL DEFAULT 0,
  -- معرّف الرسالة المقتبَسة. لا مفتاح أجنبي: الرسالة المقتبَسة قد تُحذف
  -- حذفاً ناعماً، والردّ يبقى مقروءاً بمقتطف محفوظ في العرض.
  reply_to   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS x_chat_room_time ON x_chat_messages (room_id, created_at DESC);
CREATE INDEX IF NOT EXISTS x_chat_user ON x_chat_messages (user_id, created_at DESC);

-- رفع مقاطع الدردشة متعدّد الأجزاء.
--
-- الفيديو العادي يصل عشرات الميغابايت، وحشوه base64 داخل JSON يضخّمه 4/3
-- ويمرّ كاملاً في ذاكرة العامل فينهيه (نفس سبب وجود x_course_uploads).
-- هنا نجلسة رفع قصيرة العمر: صفّ يُحذف لحظة الإكمال أو الإلغاء، وليس
-- سجلاً دائماً — الرسالة في x_chat_messages تبقى المرجع الوحيد بعد ذلك.
CREATE TABLE IF NOT EXISTS x_chat_uploads (
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
);
CREATE INDEX IF NOT EXISTS x_chat_uploads_user ON x_chat_uploads (user_id, created_at);

-- إجراءات المالك: كتم دائم (mute) وطرد (kick). room_id فارغ = كل الأقسام.
CREATE TABLE IF NOT EXISTS x_chat_actions (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  kind       TEXT NOT NULL,                  -- mute | kick
  room_id    TEXT NOT NULL DEFAULT '',
  reason     TEXT NOT NULL DEFAULT '',
  until      INTEGER NOT NULL DEFAULT 0,     -- 0 = بلا نهاية (للكتم)
  at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS x_chat_actions_user ON x_chat_actions (user_id, kind);

-- رموز أجهزة الدفع (FCM). الرمز واحد لكل تثبيت، ويُربط بمعرّف الدردشة
-- (حساب أو زائر) ليصل الإشعار لمن يهمّه وحده.
--
-- لماذا جدول منفصل عن x_installs؟ لأن الدفع يحتاج رمز الجهاز نفسه لا بصمة
-- التثبيت، والرمز يتغيّر عند إعادة تثبيت التطبيق أو مسح بياناته، فيُحدَّث
-- هنا بلا أن يمسّ سجل التثبيت.
CREATE TABLE IF NOT EXISTS x_push_tokens (
  token      TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  platform   TEXT NOT NULL DEFAULT 'android',
  updated_at TEXT NOT NULL
);
-- الإرسال يبدأ دائماً من المستخدم: «أرسل لكل من ليس أنا».
CREATE INDEX IF NOT EXISTS x_push_tokens_user ON x_push_tokens (user_id);
-- ══════════════════════════════════════════════════════════════
-- أكاديمية الدورات (فيديوهات تعليمية) — معزولة تماماً داخل x-app-db
-- ══════════════════════════════════════════════════════════════
-- كل جدول هنا ملك تطبيق X وحده. لا قراءة ولا كتابة من أي تطبيق آخر،
-- ولا أي مسار يلمس موارد phonex. الفيديوهات المخزّنة هنا مستقلّة بذاتها.

-- دورة = قائمة تشغيل. locked يعني أن القائمة مقفلة كاملة حتى يُفتح لها مفتاح.
CREATE TABLE IF NOT EXISTS x_courses (
  id          TEXT PRIMARY KEY,
  title       TEXT NOT NULL,
  subtitle    TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  cover_key   TEXT NOT NULL DEFAULT '',
  locked      INTEGER NOT NULL DEFAULT 1,
  sort        INTEGER NOT NULL DEFAULT 0,
  published   INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS x_courses_sort ON x_courses (published, sort, created_at);

-- فيديو داخل دورة. object_key مفتاح R2 الخام ولا يُرسل للعميل قبل التحقق
-- من الاستحقاق — وإلا صار الرابط نفسه مفتاحاً للسرقة.
CREATE TABLE IF NOT EXISTS x_course_videos (
  id          TEXT PRIMARY KEY,
  course_id   TEXT NOT NULL,
  title       TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  object_key  TEXT NOT NULL,
  mime        TEXT NOT NULL DEFAULT 'video/mp4',
  duration_s  INTEGER NOT NULL DEFAULT 0,
  size_bytes  INTEGER NOT NULL DEFAULT 0,
  mode        TEXT NOT NULL DEFAULT 'locked',
  sort        INTEGER NOT NULL DEFAULT 0,
  published   INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT NOT NULL,
  -- مفتاح المصغّرة داخل XLEARN. كان يُقرأ في `coursesFor` وفي مسار
  -- `/v1/learn/thumb` دون أن يُعرَّف هنا، فقاعدة تُبنى من هذا الملف وحده
  -- كانت تفشل في جلب قائمة الدورات كلياً.
  thumb_key   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS x_course_videos_order ON x_course_videos (course_id, published, sort);

-- مفاتيح الفتح. المفتاح يُخزَّن مُجزَّأً (SHA-256) لا صريحاً: من يقرأ
-- القاعدة لا يجد ما يُدخل، ولا يستطيع سرقة مفاتيح المستخدمين.
-- course_id يجعل المفتاح سارياً لدورة واحدة — مفتاح دورة لا يفتح غيرها.
CREATE TABLE IF NOT EXISTS x_course_keys (
  id           TEXT PRIMARY KEY,
  course_id    TEXT NOT NULL,
  code_hash    TEXT NOT NULL UNIQUE,
  label        TEXT NOT NULL DEFAULT '',
  max_uses     INTEGER NOT NULL DEFAULT 1,
  used_count   INTEGER NOT NULL DEFAULT 0,
  device_id    TEXT NOT NULL DEFAULT '',
  expires_at   INTEGER NOT NULL DEFAULT 0,
  revoked      INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL,
  used_at      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS x_course_keys_course ON x_course_keys (course_id, revoked);

-- سجل الاستحقاق: أي تثبيت يملك أي دورة. الربط بالتثبيت الموثّق لا بالحساب،
-- فيصمد حتى لو أنشأ المستخدم حساباً جديداً على الجهاز نفسه، ويمنع إعادة
-- استخدام المفتاح على تثبيت ثانٍ.
CREATE TABLE IF NOT EXISTS x_course_grants (
  install_id TEXT NOT NULL DEFAULT '',
  device_id  TEXT NOT NULL DEFAULT '',
  course_id  TEXT NOT NULL,
  key_id     TEXT NOT NULL DEFAULT '',
  user_id    TEXT NOT NULL DEFAULT '',
  at         INTEGER NOT NULL,
  -- الاستحقاق يُنسب إلى التثبيت الموثّق لا إلى معرّف جهاز يرسله العميل.
  -- كان فتح دورة يعتمد على `x-device-id` وحده، ومن قرأ معرّف جهاز مشترك
  -- (يظهر في الدردشة وفي تصدير اللوحة) يضعه في طلبه فيُفتح المقفل بلا كود
  -- أصلاً — أي أن كود المالك كان يمكن تجاوزه كلياً.
  PRIMARY KEY (install_id, course_id)
);
CREATE INDEX IF NOT EXISTS x_course_grants_course ON x_course_grants (course_id);

-- جلسات الرفع المُجزَّأ للفيديوهات الكبيرة.
--
-- سبب وجودها: Cloudflare يرفض أي طلب جسمه يتجاوز 100 ميغابايت على حافة
-- الشبكة قبل أن يصل إلى الـWorker أصلاً، فيرد 413 بلا أن ينفّذ سطراً واحداً
-- من كودنا. لذلك كل مقطع يتجاوز الحدّ يُرفع على أجزاء، وكل جزء طلب مستقل
-- تحت الحدّ. هذا الجدول يحفظ ربط الأجزاء بـuploadId في R2 كي يبقى الرفع
-- قابلاً للاستكمال، وحتى لا يستطيع مالك ثانٍ إكمال جلسة غيره.
CREATE TABLE IF NOT EXISTS x_course_uploads (
  id          TEXT PRIMARY KEY,
  course_id   TEXT NOT NULL,
  object_key  TEXT NOT NULL,
  r2_upload_id TEXT NOT NULL,
  title       TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  mode        TEXT NOT NULL DEFAULT 'locked',
  mime        TEXT NOT NULL DEFAULT 'video/mp4',
  size_bytes  INTEGER NOT NULL DEFAULT 0,
  parts_done  INTEGER NOT NULL DEFAULT 0,
  owner_id    TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS x_course_uploads_owner ON x_course_uploads (owner_id, created_at);

CREATE TABLE IF NOT EXISTS x_devices (
  -- المفتاح هو التثبيت الموثّق، لا معرّف الجهاز الذي يرسله العميل.
  --
  -- لماذا: `x-device-id` يرسله العميل ولا يدخل في نصّ التوقيع
  -- (`installId|ts|nonce|method|path|bodyHash`). فمن سجّل مفتاح تثبيت لنفسه
  -- — مجاناً وبلا كلمة مرور — وقّع طلباً صحيحاً ثم وضع معرّف جهاز المالك فيه،
  -- فيمرّ التوقيع ويُفتح كل مقفل بلا كلمة مرور. `install_id` هو القيمة
  -- الوحيدة التي يثبتها التوقيع بمفتاح خاص لا يغادر الجهاز.
  --
  -- `device_id` يبقى للعرض والسجل (المالك يتعرّف على هواتفه في اللوحة)،
  -- ولا يُشتقّ منه أي استحقاق.
  install_id   TEXT PRIMARY KEY,
  device_id    TEXT NOT NULL DEFAULT '',
  owner_marked INTEGER NOT NULL DEFAULT 0,
  owner_bound  INTEGER NOT NULL DEFAULT 0,
  first_seen   TEXT NOT NULL,
  last_seen    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS x_devices_owner ON x_devices (owner_marked);
CREATE INDEX IF NOT EXISTS x_devices_install ON x_devices (install_id, owner_marked);

-- ==============================================================
-- تعديلات المالك على التوافقات (طبقة فوق المصدر المشترك)
-- ==============================================================
-- لماذا جدول تعديلات لا كتابة مباشرة؟ مصدر التوافقات قاعدة مشتركة
-- (phonex-mirror) يقرأ منها تطبيق آخر، وأي كتابة فيها تغيّر بياناته.
-- فالتعديل يبقى هنا ملكاً لتطبيق X، ويُدمج مع المصدر عند العرض: الحذف
-- والإضافة يُريان هنا فقط، والمصدر لا يُمسّ.

-- doc_key = معرّف السجل في المصدر. kind: patch تعديل سجل قائم،
-- new عنصر أنشأه المالك من الصفر، cat صفة/نوع فرعي جديد.
CREATE TABLE IF NOT EXISTS x_compat_edits (
  id         TEXT PRIMARY KEY,
  doc_key    TEXT NOT NULL,
  brand_file TEXT NOT NULL DEFAULT '',
  kind       TEXT NOT NULL DEFAULT 'patch',
  data       TEXT NOT NULL,
  deleted    INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS x_compat_edits_doc ON x_compat_edits (doc_key);
CREATE INDEX IF NOT EXISTS x_compat_edits_brand ON x_compat_edits (brand_file);

-- المنحة اليومية: عدّاد ذرّي لكل (هوية/عنوان + يوم + نوع).
--
-- العدّاد في D1 لا KV لأن `INSERT ... ON CONFLICT DO UPDATE ... RETURNING`
-- يفحص الحدّ ويستهلك في UPDATE واحد، فلا سباق ولا تجاوز حتى مع الطلبات
-- المتزامنة. المفتاح المركّب يحمل الأنواع الثلاثة معاً: 'all' لمنحة الهوية،
-- و'ipfree' لسقف العنوان الذي يمنع تفريخ الهويات، و'gift' لهديّة اليوم.
CREATE TABLE IF NOT EXISTS x_quota_daily (
  uid  TEXT NOT NULL,
  day  TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'all',
  used INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (uid, day, kind)
);

-- استلام الهديّة اليوميّة: صفّ واحد لكل محفظة يحمل لحظة الاستلام ولحظة
-- الفتح التالية. المفتاح هو المحفظة لا اليوم التقويمي: بلحظة الفتح المحفوظة
-- هنا تُمنح الهديّة بعد 24 ساعة تماماً من الاستلام، فلا تضيع هديّة من استلم
-- قرب منتصف الليل ولا تُمنع هديّة من استلم بعيداً عنه.
CREATE TABLE IF NOT EXISTS x_gift_claims (
  wallet     TEXT PRIMARY KEY,
  last_at    INTEGER NOT NULL,
  next_at    INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS x_gift_claims_next ON x_gift_claims (next_at);

-- ── مفاتيح التثبيت (Ed25519) — بديل السرّ المضمّن في التطبيق ──
--
-- لماذا: التطبيق المصدَّر كان يحمل سرّاً واحداً مشتركاً بين كل النسخ. من
-- استخرجه من الحزمة يستطيع توقيع أي طلب بلا حد، ولا سبيل لإبطال ما سرّبه
-- إلا بتحديث كل الأجهزة. هنا يولّد كل تثبيت زوج مفاتيح محلياً ويرسل المفتاح
-- العام وحده. المفتاح الخاص لا يغادر الجهاز أبداً، والخادم لا يملك ما
-- ينتحل به أي تثبيت ولو سُرّبت قاعدة البيانات كاملة. الإبطال صار لكل
-- تثبيت على حدة (revoked) بدل إبطال الجميع.
CREATE TABLE IF NOT EXISTS x_install_keys (
  install_id  TEXT PRIMARY KEY,
  public_key  TEXT NOT NULL,
  device_id   TEXT NOT NULL DEFAULT '',
  app_version TEXT NOT NULL DEFAULT '',
  -- آخر طابع زمني مقبول: يمنع إعادة تشغيل طلب قديم مُعترَض داخل نافذة
  -- الصلاحية. أي طلب أقدم من آخر ما رُئي يُرفض.
  last_ts     INTEGER NOT NULL DEFAULT 0,
  revoked     INTEGER NOT NULL DEFAULT 0,
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS x_install_keys_dev ON x_install_keys (device_id);

-- ==============================================================
-- ربط محفظة الزائر بالتثبيت الموثّق (بدل بصمة يرسلها العميل)
-- ==============================================================
-- لماذا: مفتاح محفظة الزائر كان `x-device-fp` المُرسَل من العميل. ومعرّف
-- الجهاز ليس سراً — يظهر في الدردشة وفي تصدير اللوحة — فمن قرأه أرسله مع
-- بصمته وصرف رصيد الضحية بلا جلسته ولا بصمته. الربط يُخزَّن هنا مرة واحدة،
-- وبعدها المفتاح يُقرأ من هذا الجدول لا من الطلب: تغيير الترويسة لا يُنتج
-- هوية جديدة ولا يصل إلى محفظة أحد.
--
-- البصمة المملوكة لتثبيت آخر لا تُتبنّى (فريد)، فلا تُسرق محفظة قائمة؛
-- ومن كان مفتاحه بصمة حرّة يحتفظ بها وبرصيده عند أول طلب بعد الترقية.
CREATE TABLE IF NOT EXISTS x_wallet_bindings (
  install_id TEXT PRIMARY KEY,
  wallet_key TEXT NOT NULL,
  bound_at   TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS x_wallet_bindings_key ON x_wallet_bindings (wallet_key);

-- ==============================================================
-- مكافأة أول تثبيت — لكل جهاز مرة واحدة مدى الحياة
-- ==============================================================
-- المفتاح هو بصمة الجهاز (ANDROID_ID) لا التثبيت ولا المحفظة: مسح بيانات
-- التطبيق أو إعادة تثبيته يولّد تثبيتاً ومحفظة جديدين، لكن البصمة ثابتة —
-- فالصفّ هنا يبقى شاهداً على أن الجهاز أخذ مكافأته. التلاعب بوقت الهاتف
-- لا يحرّك شيئاً لأن granted_at يُكتب بساعة الخادم.
CREATE TABLE IF NOT EXISTS x_install_bonus (
  fp         TEXT PRIMARY KEY,
  install_id TEXT NOT NULL,
  granted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS x_install_bonus_install ON x_install_bonus (install_id);

-- منع إعادة إرسال الطلبات الحسّاسة بعينها (nonce فريد لكل طلب).
-- يُطبَّق على المسارات التي تغيّر حالة أو تستهلك رصيداً، لا على كل قراءة:
-- كتابة صفّ لكل طلب قراءة كان سيرفع الكلفة بلا مقابل أمني حقيقي، فحرس
-- القراءات يبقى الطابع الزمني والحدود على المعدّل.
CREATE TABLE IF NOT EXISTS x_req_nonces (
  install_id TEXT NOT NULL,
  nonce      TEXT NOT NULL,
  at         INTEGER NOT NULL,
  PRIMARY KEY (install_id, nonce)
);
CREATE INDEX IF NOT EXISTS x_req_nonces_at ON x_req_nonces (at);
