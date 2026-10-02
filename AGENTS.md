# XApp — ملاحظات العمل

تطبيق Flutter (عميل) + Cloudflare Worker (خادم). التطبيق يقرأ من Worker خارجي
عبر اتصال موقّع بـ HMAC. لا نكتب في أي مورد مشترك مع تطبيقات أخرى.

## بناء APK

```bash
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export ANDROID_HOME=/workspace/tools/android-sdk
export ANDROID_SDK_ROOT=/workspace/tools/android-sdk
export PATH=/workspace/tools/flutter/bin:$PATH
cd app
flutter build apk --release                                    # 76MB لكل المعالجات
flutter build apk --release --target-platform android-arm64 --split-per-abi  # 27MB
```

الناتج: `app/build/app/outputs/flutter-apk/`.

### التوقيع

المستودع يدعم keystore إصدار عبر `app/android/key.properties` (مستثنى في
`.gitignore`). المفتاح الدائم الموجود:

- `app/android/app/x-release.jks` + `app/android/key.properties` (نسخة في `D:\XApp\app\android\`)
- alias: `xkey` · sha256: `20a5b58c37da45bf00cc2ca1b573be9337dceae0370f559d9e275c848b272d1c`
- تنبيه: مفتاح `xapp-release.jks` الموثّق سابقاً (sha256 `032f8c38…`) ضاع مع
  بيئة العمل القديمة، والنسخة على الهاتف كانت بشهادة أخرى (`fb8fe9dc…`)
  فتطلّب التثبيت حذفها. **كل بناء جديد يجب أن يكون بمفتاح `x-release.jks`
  هذا** وإلا رفض أندرويد التحديث مرة أخرى.

بدون `key.properties` يُستخدم مفتاح debug فيتغيّر التوقيع ويرفض أندرويد
التحديث فوق النسخة القديمة. لذلك استخدم المفتاح الدائم دائماً.

ملاحظة بيئة: قرص C: كان يمتلئ فيفشل `assembleRelease` بـ«no space» — نُقلت
ذاكرة Gradle إلى `D:\gradle-home` ويُبنى بـ `GRADLE_USER_HOME=D:\gradle-home`.

### متطلبات البيئة بعد إعادة التهيئة

```bash
apt-get update && apt-get install -y openjdk-21-jdk-headless
```

## نشر نسخة للتنزيل

```bash
cp app/build/app/outputs/flutter-apk/app-release.apk       /workspace/dist/X-app-vX.Y.Z.apk
cp app/build/app/outputs/flutter-apk/app-arm64-v8a-release.apk /workspace/dist/X-app-vX.Y.Z-arm64.apk
cd /workspace/dist && sha256sum *.apk | tee SHA256.txt
# حدّث الروابط والبصمات في index.html
pgrep -f "http.server 12000" || (cd /workspace/dist && setsid nohup python3 -m http.server 12000 --bind 0.0.0.0 > server.log 2>&1 &)
```

الرابط العام: `https://work-1-uqpzekbyhjvrxjks.prod-runtime.all-hands.dev/`

## الفحص

```bash
cd app && flutter analyze lib          # يجب: 0 errors / 0 warnings
BT=/workspace/tools/android-sdk/build-tools/36.0.0
$BT/aapt2 dump permissions build/app/outputs/flutter-apk/app-release.apk
$BT/apksigner verify --print-certs build/app/outputs/flutter-apk/app-arm64-v8a-release.apk
```

## حقائق مهمة عن الخادم (مقيسة)

توقيع الطلب: `HMAC-SHA256(secret, "<deviceId>|<ts>|<METHOD>|<path+query>")` مع
الترويسات `x-device-id`, `x-app-ts`, `x-app-sig`, `x-app-version`, `User-Agent: X-App/1.0.0`.

- `GET /v1/data/compatibility` يقبل `q`, `brand`, `type`, `limit`. **`limit` أقصاه
  500 فعلياً**.
- `POST /v1/data/compat/search` هو مسار البحث المعتمد. يقبل `{q, brand, type}`.
  يرجع `{records, types, charged, remaining}`.
- **البحث صار على الخادم**: البحث المحلي السابق كان يحمّل ملف الشركة كاملاً
  (~65KB و0.9 ثانية) عند كل دخول. الآن الكتابة تُرسَل للخادم. لا تعدّل بنية المرآة
  — موارد مشتركة مع تطبيق آخر — لكن استعلام `LOWER(data) LIKE ?` داخل
  `mirrorSearchCompat` يعمل ولا يحتاج `search_text`.
- **استعلام فارغ لا يُخصم**: يرجع `types` فقط (بلا `records`) لبناء صف الأنواع،
  وهو سلوك النقطتين. لا تُعِد الخصم على `q=''` وإلا استُنزف المشترك بمجرد فتح شاشة.
- يقولب `type` يعمل ويرجع أنواعاً مختلفة.
- 15 شركة، ~1256 سجلاً. أنواع القطع: `SCREEN`, `BATTERY`, `GLASS`, `INCASSABLE`.

## مكافأة أول تثبيت (installBonus)

`/v1/install` يمنح `settings.installBonus` عملة (افتراضي 10، 0 = معطّلة،
يضبطه المالك عبر PUT /v1/owner/settings) في محفظة الزائر **مرة واحدة لكل
جهاز مدى الحياة**. المفتاح `x_install_bonus.fp` هو `x-device-fp`
(ANDROID_ID) — يبقى بعد مسح البيانات وإعادة التثبيت، والقرار والطابع
بساعة الخادم فلا تأثير لتلاعب وقت الهاتف. بلا بصمة صالحة لا منحة:
هوية هشّة تعيد إنتاج نفسها لا تستحق. الردّ يحمل `bonus` الرقم الممنوح.

## نظام العملات في التوافقات

البحث الواحد يُخصم من رصيد بطاقات المخططات (نفس العملة، لا نظام منفصل).

- الثمن من `settings.compatSearchCost` (ضبطه المالك، 0=مجاني، الافتراضي 1).
- **الخصم مرة واحدة لكل استعلام جديد**: بصمة `cq:<uid>:<hmac>` بمهلة 900 ثانية
  تجعل إعادة البحث نفسه أو التنقل بين النتائج مجانياً. كل نص جديد يكلّف — وهذا
  ما يمنع سحب التوافقات آلياً.
- **البصمة تُكتب بعد نجاح الخصم فقط**: كتابتها قبله كانت تمنع أي بحث آخر خلال
  النافذة من الخصم حتى لو تغيّر النص.
- `consumeFileQuota` تخصم ذرياً (`UPDATE ... WHERE quota_balance > 0 RETURNING`)
  فسباق الطلبات لا يعطي بيانات مجانية، و`consumeFileQuota` هي موضع تسجيل
  البصمة الوحيد (تسجيلها مرتين كان يفسد نافذة السماح).
- التطبيق ينتظر 280ms بعد آخر ضغطة مفتاح قبل الطلب (debounce) ويسقط الردود
  القديمة بـ `_seq` — أقل استهلاكاً وأسرع إحساساً من طلب لكل حرف.
- `Api.searchCompatCharged` يتراجع لـ `GET /v1/data/compatibility` عند 404 فقط،
  كي يعمل التطبيق قبل نشر الخادم الجديد.

## رابط تيليجرام والباقات: مصدر واحد

الوجهة يحددها المالك من لوحته (`settings.telegramLink`) — **لا رابط مثبت في
الكود**. `lib/core/app_config.dart` هو المصدر الوحيد:

- `load()` عند الإقلاع: يقرأ من `SharedPreferences` فيعمل بلا شبكة.
- `applyBootstrap(boot)` من ردّ `/v1/bootstrap` (يُمرَّر جاهزاً، بلا جلب مكرر).
- `applyOwnerSettings(...)` بعد حفظ المالك — يشمل الشاشات المفتوحة فوراً عبر
  `notifyListeners` (تستمع لها `Shell`).
- رابط فارغ من الخادم **لا يمحو** رابطاً صالحاً محفوظاً. و`reset()` يمسحه
  للاختبارات فقط.
- `openExternal` يتعامل مع الرابط الفارغ برسالة واضحة بدل الفشل الصامت.

عند إضافة أي شاشة تستخدم تيليجرام: اقرأ `AppConfig.instance.telegram`، ولا
تضع قيمة افتراضية. لتجهيز رسالة: `shell.dart::_tgWithText` (يستخدم `&` إن كان
في الرابط استعلام مسبقاً).

## فتح تيليجرام: مخطط tg:// لا https

أندرويد يربط مخطط `https` بالمتصفح افتراضياً، فرابط `https://t.me/...` **لا**
يفتح تيليجرام إلا إن اختار المستخدم «افتح دائماً» فيه. لذلك كل «تواصل مع
المالك» كان ينتهي في المتصفح.

- `external_link.dart::telegramAppUri` يحوّل `https://t.me/<اسم>` إلى
  `tg://resolve?domain=<اسم>`، ويحفظ `text`/`start` كما هي، ويحوّل الدعوات
  `+مفتاح` إلى `tg://join?invite=`. يرجع `null` لغير روابط تيليجرام.
- `openExternal` يجرّب مخطط التطبيق أولاً ثم الرابط الأصلي، ويحفظ `text`
  كي تصل الرسالة الجاهزة. لا تعتمد على `canLaunchUrl` وحدها.
- الروابط غير التابعة لتيليجرام لا تُمس (تحقق صارم من النطاق).

## شاشة التوافقات: النوع أولاً

`compat_brand_screen.dart` يستعلم الخادم أثناء الكتابة داخل نطاق الشركة والنوع.
`CompatTypeMeta` يحمل اسم كل نوع وأيقونته ولونه وترتيبه.

- **لا أعداد في صف الأنواع**: الأيقونة والاسم فقط.
- لا نتائج قبل اختيار النوع وكتابة الاستعلام.
- `CompatBrand.ref` يرسل `v_poco` للشركات الفرعية ليصفّيها الخادم على كلمتها.
- الشركات الفرعية تتداخل مشروعاً (POCO ∩ Redmi = سجلات تذكر الفرعيتين)،
  فالتقاطع ليس خطأً.
- عند الخصم يظهر رصيد البطاقات كشريحة في شريط العنوان، وعند النفاد حوار
  يوجّه للباقات بدل رسالة خطأ صامتة.
- `compat_catalog.dart` بقي لـ `normalizeModel` و`rankModels` (إبراز وترتيب
  النتائج) — لم يعد يبني فهرساً محلياً كاملاً.

## أول تشغيل: «تعذر الاتصال تحقق من الإنترنت»

كانت `splash.dart` تعيد المحاولة في حلقة صامتة بلا حد ولا مخرج. الآن:

- تُعاد المحاولة تلقائياً 3 مرات بتراجع تدريجي (600ms × رقم المحاولة) —
  يراعي شبكة أول تشغيل البطيئة.
- عند الفشل يظهر **زر «إعادة المحاولة»** برسالة واضحة، بدل انتظار بلا نهاية.
- الاستثناءات غير الشبكية (خطأ من الخادم مثلاً) لا تُعاد — إعادة المحاولة بلا
  فائدة تُطيل الانتظار.
- `flutter analyze lib` يجب أن يبقى 0 error / 0 warning.
- اختبارات `app/test/` تحمي هذه السلوكيات: الثيم الداكن الافتراضي، اسم PhoneX،
  معرّف الحزمة الثابت، واستقلال شعارات الشركات.

## الهوية الحالية: PhoneX

الاسم الظاهر للتطبيق **PhoneX** (`kAppName` في `lib/core/config.dart` و
`android:label` في البيان). معرّف الحزمة بقي `com.xapp.x_app` **قصداً**: تغييره
يجعل أندرويد يعامله تطبيقاً جديداً فلا تُثبَّت التحديثات فوق النسخة القائمة،
ويضيع ما على جهاز المستخدم.

- **الثيم الداكن هو الافتراضي** (`XTheme.isLight = false`). تهيئة الحالة الثابتة
  تسبق قراءة تفضيل المستخدم، فإن كانت فاتحة ظهر وميض فاتح في أول إطار قبل أن
  يُطبَّق اختيار المستخدم المحفوظ.
- الخط `IBM Plex Sans Arabic` بدل `Tajawal`: الأشكال العربية في الأول أقرب إلى
  ما اعتاده المستخدم في الأنظمة، ومعها عربات أرقام أوضح.
- معرّفات قنوات الإشعارات `phonex_announcements` و`phonex_chat`، ويجب أن تطابق
  قيمة `com.google.firebase.messaging.default_notification_channel_id` في
  البيان — اختلافهما يجعل إشعار FCM الواصل على القناة الافتراضية بلا أهميتها.

### الفصل عن تطبيق PhoneX الأصلي على Cloudflare

التطبيقان يتشاركان حساب Cloudflare، والفصل مقصود ومكتوب في `worker/wrangler.toml`:

- الموارد **المشتركة قراءة فقط**: `phonex-mirror` (D1) و`phonex-schematics` (R2).
- موارد التطبيق مستقلة تماماً: `x-app-db` (D1)، `x-app-media` و`x-app-learn`
  (R2)، ومساحة `QUOTA` (KV). لا نكتب في مورد مشترك أبداً.
- دلو إصدارات التطبيق `xapp-releases` منفصل عن أي دلو يخص التطبيق الآخر.
- كل مشكلة في هذا المستودع تُصلح في مورد التطبيق، لا في المشترك.

## أندرويد: أخطاء متكررة

- **`INTERNET` غير موجود في release**: قالب Flutter يضعه في debug/profile فقط.
  يجب إعلانه في `app/android/app/src/main/AndroidManifest.xml` وإلا يفشل كل اتصال
  برسالة «تعذر الاتصال تحقق من الإنترنت».
- **فتح تيليجرام/الروابط يفشل صامتاً**: أندرويد 11+ يخفي التطبيقات غير المعلَنة.
  يجب إعلان `<queries>` مع `scheme https/http/tg` وحزم تيليجرام، وإلا يعيد
  `canLaunchUrl` القيمة `false`. استخدم `openExternal` في `lib/ui/external_link.dart`
  ولا تستخدم `canLaunchUrl` كشرط لإطلاق الرابط.
- **البصمة لا تتفعّل صامتة**: `local_auth_android` يعرض نافذة البصمة عبر
  `Fragment`، فيحتاج النشاط أن يرث `FlutterFragmentActivity` لا `FlutterActivity`.
  مع `FlutterActivity` يرجع `authenticate()` بلا نافذة وبلا خطأ ظاهر — أشبه
  بمفتاح لا يفعل شيئاً. الأثر في `MainActivity.kt` وحده.
- **`LaunchTheme`/`NormalTheme` بـ`parent` من `android:` تنهار على أندرويد 8-**
  عند عرض نافذة البصمة؛ استخدم `Theme.AppCompat.*.NoActionBar` في
  `res/values/styles.xml` و`res/values-night/styles.xml` معاً.
- **`USE_BIOMETRIC` لا يُعلَن يدوياً**: قالب `local_auth_android` يعلنه في
  manifest الملحق فيُدمج تلقائياً. إعلانه في manifest التطبيق زيادة بلا فائدة.

## توزيع النسخ: الرابط الدائم على Cloudflare R2

خادم التحميل المحلي (`/workspace/serve_dist.sh`، منفذ 12000) يعمل داخل بيئة
العمل المؤقتة و**يموت كلما أُعيد إنشاء البيئة** فيتوقف الرابط ويشكو المستخدم
أن «خادم التحميل لا يحمل». حلقة `while true` لا تكفي لأن إعادة إنشاء البيئة
تقتل العملية الأم أيضاً.

الرابط الدائم المعتمد (لا يعتمد على بيئة العمل):

```
https://pub-8da12185716441d4bcdcd4c49f395174.r2.dev/download.html
```

- الحاوية: `xapp-releases` على حساب Cloudflare، عامة عبر managed domain.
- الملفات: `PhoneX-v<النسخة>.apk` مع نسخ `-arm64` و `-armeabi-v7a` و `-x86_64`.
- الرفع عبر API بلا wrangler:
  `curl -X PUT https://api.cloudflare.com/client/v4/accounts/<ACC>/r2/buckets/xapp-releases/objects/<name> -H "Authorization: Bearer <token>" --data-binary @<file>`
  التوكن في `/workspace/.cf_token` والحساب `4b386375f3294750ffdb6f89de3a09db`.
- صفحة التنزيل تُنشر باسم `download.html` لأن روابطها نسبية فتعمل كما هي.

عند كل نسخة جديدة: ارفع الحزم الأربع مع `download.html` و `SHA256.txt`، وتأكد
أن بصمة الملف المنزّل من الرابط تطابق `sha256sum` المحلي.

### رفع الدردشة: حدّ الحجم والقطعة

تكرار الشكوى «فيديو الدردشة لا يُرفع» كان لسببين متراكبين، كلاهما يُظهر فشلاً
عاماً بلا رسالة مفيدة:

- سقف الوسائط في الخادم (`chatMaxMediaMb`) كان يُقصّ عند 25، فأي فيديو أكبر
  يُرفض من الباب. القصّ الآن `Math.max(1, Math.min(200, ...))` في مكاني
  التحقق والتحديث معاً — تفاوت بينهما يعني حدّاً يُعرض للمالك ولا يُطبَّق.
- `CHAT_UPLOAD_CHUNK` كان 4MiB، وهو **أقل من الحد الأدنى لـ R2 multipart
  (5MiB) لكل قطعة عدا الأخيرة**. النتيجة: أي ملف يتجاوز 4MiB يفشل عند التقسيم.
  القيمة الآن 8MiB، والاحتياطي في التطبيق (`lib/core/api.dart`) لا ينزل تحت
  5MiB أبداً.

درس عام: أي رفع multipart إلى R2 يجب أن تبقى قطعته ≥5MiB، وإلا نجح الاختبار
على ملف صغير وفشل على كل ملف حقيقي.

### بثّ الدروس: روابط موقّعة لا وكيل محلي

الوكيل المحلي (`media_proxy.dart`) الذي كان يوقّع كل طلب Range أُزيل من
مسار الدروس: كان يُعلّق `initialize()` على الشبكات الضعيفة ويفشل كل
تشغيل. الآن `coursesFor` يُسكّ رمزاً موقّعاً بـHMAC (`?i=<install>&e=<exp>
&s=<hmac>`، صلاحية 6 ساعات) لكل فيديو مُستحَقّ فقط، ومعالج
`/v1/learn/stream/:id` يتحقق منه بـ`crypto.subtle.verify` ثم يعيد فحص
`courseUnlocked`/`ownerDevice` و`videosHidden` قبل أي بايت من R2. طلبات
الرمز معفاة من `verifySignature` و`authenticate` (المشغّل لا يرسل
ترويسات) — الإعفاء ليس تفويضاً، التحقق داخل المعالج. المسار القديم
(ترويسات موقّعة) يبقى مدعوماً. درس عام: **لا تبنِ وسائط عبر وسيط محلي**
— روابط موقّعة قصيرة العمر أبسط وأسرع وأصلب.

### الشاشة السوداء في فيديو الدروس

`VideoPlayerController.initialize()` كان بلا مهلة. تعليق الخادم المحلي
(`VideoStreamServer`) دون وصول رأس الملف يُبقي `initialize` معلّقاً للأبد،
والملصق داكن (`#0E1116`) بلا أي نصّ انتظار — فيبدو كشاشة سوداء متجمدة لا
انتظاراً. عولج بثلاث نقاط في `courses_screen.dart`:

- مهلة 25 ثانية على `initialize` في المسارين (البثّ المتزايد والتنزيل الكامل)،
  وعند انقضائها يُعاد إلى المسار الاحتياطي بدل الجمود.
- تشغيل شريط التقدّم في المسار الاحتياطي أيضاً: تنزيل دقائق بلا حركة يُقرأ
  كعطل.
- عرض `v.hasError` مع زر إعادة محاولة، فالترميز غير المدعوم والملف التالف
  كانا يُتركان سطحاً أسود صامتاً.

## ترتيب نتائج بحث التوافقات (طبقة الخادم)

`mirrorSearchCompat` كان بلا `ORDER BY`، فيُعيد D1 صفوفه بترتيب تخزين
اعتباطي: بحث «note 12» يعرض سجلاً فيه `note 12s` قبل سجل فيه `note 12 pro+`.
الحل: جلب حتى `limit*3` صف ثم ترتيبها في JS عبر `relevanceScore`
(مطابقة تامة في موديل > بداية موديل > احتواء > نوع فرعي > أي نص)، مع توحيد
المسافات لأن البيانات تكتب الموديل صيغتين («note 12» و«note12pro»).

الترتيب في JS لا في SQL عن قصد: أسماء حقول `data` JSON غير موثّقة في المخطط،
فـ`json_extract` على اسم مخمّن يهشّ؛ حقول التوافقات الفعلية هي
`compatibleModels` (قائمة) و`subCategory` (كائن فيه `name`) و`componentType`.
اختبار الحراسة: `app/test/compat_search_order_test.dart`.
## بناء APK (بيئة بلا Android SDK)

البيئة لا تأتي بـ Java ولا Android SDK ولا `unzip`. الحلول التي نجحت:

- JDK: حزمة محمولة من Adoptium إلى `/workspace/jdk17`
  (`api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse`).
  `openjdk-17-jdk-headless` غير موجود في مستودع apt هنا.
- SDK: `cmdline-tools` ثم `platforms;android-35` و`build-tools;35.0.0`.
  ثبّت `CMake 3.22.1` تلقائياً أول بناء (من `pdfrx`).
- فكّ `cmdline-tools.zip` بـ `zipfile` من Python: `unzip` غير مثبّت، وفكّه
  بأداة أخرى يُفقد صلاحية التنفيذ فتفشل `sdkmanager` بـ `Permission denied`
  — أضف `chmod +x bin/*` بعد الفكّ.
- المتغيّرات: `JAVA_HOME=/workspace/jdk17`،
  `ANDROID_HOME=ANDROID_SDK_ROOT=/workspace/android-sdk`.
- البناء يستغرق ~6 دقائق؛ شغّله في الخلفية واقرأ `/tmp/apk_build.log`.
- `flutter build apk --release` يخرج APK واحداً لكل المعماريات (80MB).
  للملفات المفصولة: `--split-per-abi`.

تحقق قبل التسليم: `apksigner verify --print-certs` (يجب أن تطابق SHA-256
بصمة `xapp-release.jks`، وإلا فالتوقيع تصحيح لا إصدار)، و`aapt2 dump badging`
لـ versionCode/versionName، ووجود `android.permission.INTERNET`.

## فحص نوع الوسائط (فخّ عائلة MP4)

مهم لرسائل الصوت: `mp4` و`m4a` و`3gp` تشترك كلها في علامة `ftyp` عند البايت
الرابع. جدول `MEDIA_SIGNATURES` بمقارنة أول تطابق كان يصنّف **كل** ملف m4a
فيديوَ، لأن قاعدة mp4 تسبقه — أي أن كل رسالة صوتية عُرضت بمشغّل فيديو.
التمييز في `sniffMp4Family`: العلامة الداخلية (bytes 8..11: `M4A `/`isom`/`3gp`)
ثم وجود مسار `vide` أو `soun`. افحص مقدّمة الملف وذيله (64KB) فقط: مسارات
`moov` قد تأتي في الآخر، وقصّ الملف كاملاً يُكلف على المقاطع الكبيرة.

اختبار عائلة MP4 في `/tmp/` كان يتحقق بست حالات (faststart، moov في الآخر،
3gp، وبدون مسارات). أعِد مثلها عند تغيير الفحص.

## إعادة إنتاج الـ worker محلياً للاختبار

`wrangler dev --local --port 8788` على نسخة `/tmp/wtest` (بذرة D1 فيها
حمزة/سوسو/سوس)، مع إضافة الأعمدة الجديدة عبر:
`wrangler d1 execute x-app-db --local --command "ALTER TABLE ..."`.
التوقيع JWT في الاختبار المحلي بسرّ ثابت — لا تخلط بينه وبين الإنتاج.

جرّد الأعمدة عن بعد قبل النشر:
`wrangler d1 execute x-app-db --remote --command "ALTER TABLE x_chat_messages ADD COLUMN media_seconds INTEGER NOT NULL DEFAULT 0"`.
إضافة عمود في الكود بلا تطبيق الهجرة يُفشل الإدراج في الإنتاج.

## واجهة الدردشة: ملء شاشة دائم

الدردشة تعمل بملء الشاشة **تلقائياً** بمجرّد فتح تبويبها — لا زر تكبير
(`Icons.fullscreen` ممنوع في `shell.dart` و`chat_screen.dart`، واختبار
`chat_fullscreen_test.dart` يحرس ذلك). الغلاف يشتق الحالة من `_chatOpen => _tab == 2`
فلا تُخزَّن في حقل يُنسى تصفيره. `_lastNonChatTab` يحفظ التبويب السابق للرجوع إليه.

**لا تُبنَ واجهة الدردشة يدوياً، ولا تُزجّج فوق هذا الثيم.** جرّبنا الزجاج
(`BackdropFilter` + طبقة بيضاء شفّافة) فاختفى المحتوى: ألوان `XTheme.surface`
معتمة، والوضع الفاتح أبيض على أبيض — المستخدم رأى «لا شيء». الأسطح هنا معتمة
(`XTheme.surface`)، والاختبار يمنع عودة `BackdropFilter` إلى هذا الملف.

**المطلوب بدله: مصدر مفتوح جاهز.** `flutter_chat_ui` (Flyer Chat، Apache-2.0)
مدعوم عربياً و RTL رسمياً ومستقل عن الخادم، وهو المرشّح المعتمد للاستبدال.

لوحة المفاتيح تتجاوز المحتوى السفلي، فالكومبوزر يلفّ نفسه بـ`SafeArea(top:false)`.

## تنبيهات «توقيع مزوّر» في لوحة المالك

سجل الأمان في اللوحة يعرض `bad_signature` لأي طلب فشل تحقق JWT. هذه التنبيهات
قد تكون منك أنت: أي سكربت اختبار (مثل `/tmp/probe.py` أو أي أداة تفحص
`/v1/chat/messages`) يرسل توقيعاً غير صالح يُسجَّل فوراً ويبدو كاختراق.

افرز الحقيقة بحقل الجهاز لا بالعدد: `cht-a-0001` مثلاً موجود في سكربتات الاختبار
فقط ولا وجود له في `app/lib`، فمعناه أن المصدر اختبار لا مهاجم. اربط الحدث
بالمصدر قبل أي استنتاج. عند التحقيق، اقرأ السجل من الخادم عبر `live.py` لا من
نسخة محلية.

## الإشعارات: وجهة الضغط، والدردشة، والدفع

**لا إشعار بلا وجهة.** `payload` يحمل `{"k":"chat","r":"<room>"}` أو `{"k":"ad"}`،
و`NotificationTarget.decode` يرفض أي حمولة لا يعرفها بدل فتح شاشة عشوائية.
ثلاثة مسارات يجب أن تعمل جميعها والحمولة نفسها تحملها: التطبيق مفتوح
(`onDidReceiveNotificationResponse`)، في الخلفية، ومغلق تماماً
(`onDidReceiveBackgroundNotificationResponse` — لازمة `@pragma('vm:entry-point')`).
في حال الإغلاق التام يبدأ أندرويد معزلاً بلا واجهة، فالوجهة تُكتب في
`SharedPreferences` (`x_notif_pending`) ويسحبها الغلاف عند أول إطار؛ ومكوّن
الإشعارات يعيدها أيضاً عبر `getNotificationAppLaunchDetails()`.

الغلاف يوجّه: الدردشة ⇒ `_openRoomId` + `_tab = 2`، والإعلان ⇒ `_tab = 0`.
الشاشة باقية في `IndexedStack` فلا `initState` جديد — التبديل يقع في
`didUpdateWidget` عند تغيّر `openRoomId`، والأفضلية لـ`_switchRoom` القائم.

**منع الإشعار المزعج أو الكاذب** في `ChatNotifyGate` (منطق صافٍ، مُختبَر في
`test/notifications_logic_test.dart` — 21 فحصاً): لا إشعار لرسالتي أنا، ولا
للقسم المفتوح أمام المستخدم (`_activeRoomId` يمليه `onRoomChanged`)، ولا حين
تكون الدردشة موقوفة أو المستخدم كاتم. **أول نبضة لكل قسم تؤسّس الختم الزمني
ولا تُنبّه** — بلا هذا يصل إشعار بكل تاريخ المحادثة لحظة التثبيت.

قناتان منفصلتان: `mapx_announcements` و`mapx_chat`. الفصل مقصود: من كتم
الإعلانات يبقى يعرف أن أحداً ناداه في الدردشة.

**الدفع (FCM) مهيّأ في الخادم ومعطّل بهدوء في العميل.** الخادم يحتوي
`x_push_tokens` و`/v1/push/register` و`pushRoomMessage`/`pushToAll` على FCM v1
(توقيع JWT بـRS256 بحساب الخدمة). كل ذلك **صامت** حتى يُضبط السرّ
`FCM_SERVICE_ACCOUNT` (JSON حساب الخدمة)، فيظهر `pushed: false` في رد نشر
الإعلان. العميل اليوم على الاستقصاء الدوريّ (20 ثانية للدردشة، 5 دقائق
للإعلانات): يصل الإشعار حين يفتح المستخدم التطبيق أو يعود إليه، **لا وهو مغلق
تماماً**. لتفعيل الدفع الحقيقي في العميل: أضف `firebase_core` و`firebase_messaging`
و`google-services.json` من مشروع Firebase، ثم استدعِ `/v1/push/register` بالرمز.
لم يُضَف شيء من ذلك بعد لأن **لا مشروع Firebase ولا `google-services.json` في
المستودع** — الإضافة بلا مفاتيح تعني كوداً لا يعمل ولا يُختبر.

## بيئة البناء — تُصفَّر مع كل إعادة تشغيل للحاوية

إعادة تشغيل الحاوية **تُمحي** `JAVA_HOME` و`ANDROID_HOME` وتُقلّص `~/.pub-cache`
(بقي 101 حزمة من 223). أعراض ذلك: `No Android SDK found`، و
`JAVA_HOME is set to an invalid directory`، وأخطاء
`Error when reading '.../pub-cache/.../flutter_local_notifications-22.3.1/...': No such file or directory`
المتكرّرة في `dart_plugin_registrant.dart` — **وهي ليست أخطاء كود**.

قبل أي بناء أعد الثلاثة:

```bash
sudo apt-get update && sudo apt-get install -y openjdk-21-jdk-headless
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH
export ANDROID_HOME=/workspace/tools/android-sdk
export ANDROID_SDK_ROOT=/workspace/tools/android-sdk
flutter pub get    # ضروري: يُعيد ما مُحي من pub-cache
flutter build apk --release
```

`android/local.properties` يشير إلى `sdk.dir=/workspace/tools/android-sdk`.
التوقيع جاهز في `android/key.properties` (لا تُطبع كلماته).

**لا تُبنَ في المقدمة بمهلة طويلة**: البناء يستغرق ~4 دقائق ويتجاوز حدّ
الأوامر. شغّله في الخلفية وتابع السجل:
`nohup flutter build apk --release > /tmp/apk_build.log 2>&1 &`.

الناتج: `build/app/outputs/flutter-apk/app-release.apk`، ويُنشر في `dist/`
باسم الإصدار مع `sha256sum`. للتحقق من التوقيع:
`apksigner verify --print-certs` من `build-tools/36.0.0`.

## قفل الإصدارات (versionGate)

`versionGate` في `worker/src/index.ts` يقارن `x-app-version` (رقم البناء) بـ
`settings.minVersion` وبقائمة `settings.blockedVersions`، ويردّ **426** مع
`update.{message,url,imageUrl}`.

- **`/v1/bootstrap` و`/v1/owner*` مستثنيان من البوابة.** بدون استثناء bootstrap
  يصل القفل بلا رسالته فيرى المستخدم خطأ اتصال لا كلام المالك؛ وبدون استثناء
  اللوحة يُقفل المالك خارج لوحته إن رفع الحدّ فوق إصدار تطبيقه.
- **`bootstrap` يجب أن يحمل `blockedVersions` و`appLocked` و`lockMessage`** —
  كانت ناقصة، فإيقاف إصدار بعينه من اللوحة لم يكن يصل للتطبيق إطلاقاً.
- **حقل «أدنى إصدار» رقم بناء لا اسم إصدار.** كتابة `1.4.0` فيه تُحلَّل بـ
  `int.tryParse` إلى null؛ كان `?? 1` يبتلعها بصمت فيُحفظ 1. القواعد الآن في
  `app/lib/core/version_rules.dart` ومفحوصة في `owner_version_validation_test.dart`.
- **`kAppVersion` في `app/lib/core/config.dart` يجب أن يساوي رقم البناء في
  `pubspec.yaml`** (حالياً 20). الخادم يقرأ ترويسة `x-app-version` لا
  `versionCode` في البيان، فنسخ `--split-per-abi` تحمل `versionCode` مُزاحاً
  (arm64=2020) بلا أثر على البوابة.
- الالتقاط في `app/lib/core/api.dart`: ردّ 426 يُطلق `VersionLock` العام،
  فيُغلق التطبيق من موضع واحد حتى لو وقع القفل أثناء جلسة قائمة.

الفحص الحقيقي: `flutter test test/version_lock_live_test.dart` — يوقّع طلباً
برقم بناء قديم ويتوقّع 426، ثم يتأكد أن النسخة الحالية تمرّ بـ200.

## تحقق محلي على Windows

- Flutter الموجود محلياً: `D:\flutter\bin\flutter.bat`. شغّله عبر PowerShell
  باستخدام `& 'D:\flutter\bin\flutter.bat'`؛ غيابه عن PATH لا يعني غياب SDK.
- فحوص التوافقات والحصة المحلية، بلا اتصال بالإنتاج:
  `node --test test/compat_quota_local.test.mjs` من `worker/`، باستخدام Node 24.
  الاختبار ينفذ كود المسارات مع SQLite في الذاكرة وبديل لواجهة D1؛ ليس اختباراً
  على Cloudflare المنشور. يغطي الحفظ والقراءة وحذف النص والحصة والتراجع الذري.
- فحوص Flutter المرتبطة:
  `flutter test --no-pub test/compat_owner_inline_edit_test.dart test/compat_owner_security_test.dart test/gift_screen_render_test.dart test/gift_wheel_test.dart`.
- اختبارات قراءة المصدر تطبّع CRLF إلى LF قبل البحث عن حدود الدوال.
- الحصة المطلوبة واحدة: `dailyFreeQuota` مصدر مبلغ العجلة، و`dailyGiftAmount`
  اسم توافق قديم للقيمة نفسها. لا حصة تلقائية فوق رصيد الاستلام. الاستلام
  التالي بعد 86400000 ميلي ثانية من السابق، ويجب نشر Worker مع تحديث التطبيق.
- رد تعديل التوافقات يتضمن `record` المحفوظ؛ الواجهة تحدّث هذا الصف دون إعادة
  البحث. قاعدة المرآة تبقى للقراءة فقط، والحفظ في `x_compat_edits` الخاصة بـXApp.


## KV: حدّ الكتابة اليومي — سبب «المكافأة لا تعمل» و«عدد التثبيتات ثابت»

- الخطة المجانية في Cloudflare KV تسمح بـ1000 كتابة/يوم. عند بلوغها يرمي
  `env.QUOTA.put` خطأً: `KV put() limit exceeded for the day.`
- كل كتابة KV على مسار طلب يجب أن تكون محمية (`try/catch` أو `.catch()`)
  إلا إذا كان فشلها يعني رفض الطلب عن قصد. كتابة عدّاد/كاش غير محمية كانت
  تُصعّد الفشل إلى 500 وتسقط المسار كاملاً.
- الحادثة الفعلية: `trackDeviceFarm` كان يكتب `devs:<ip>` في كل طلب بلا حماية؛
  فسقط `/v1/install` بـ500 طوال اليوم، فلم يُسجَّل أي تثبيت جديد ولم تُمنح أي
  مكافأة. عدد التثبيتات بقي 15 واللوحة بدت «متجمدة». الإصلاح: قراءة/كتابة
  العدّاد في `try/catch`، والطلب يمضي.
- نقاط أخرى حُميت بنفس المنطق: `cached()`، `noteOwnerLoginFail`، وفرع
  `trackDeviceFarm` للحظر التلقائي.
- للتشخيص السريع من الإنتاج: اقرأ `x_security` حيث `reason='server_error'` —
  الحقل `detail` يحمل نصّ الخطأ الأصلي، وهو ما كشف `KV put() limit exceeded`.

## سعر صفر = مجاني صراحةً (لا «لم يُحدَّد»)

- في `chargeOne`، السعر الصريح صفر يعني مجاني: `cost <= 0` يُعيد `source:'free'`
  قبل أي خصم أو رسالة «انتهت حصتك». لا تستعمل `|| 1` على سعر يضبطه المالك —
  كانت تحوّل الصفر واحداً فيُخصم من العملات رغم اختيار المجانية.
- `null` وحده يعني «لم يُحدَّد» فيرجع لـ`compatSearchCost`. حقول العرض تستعمل
  `Math.max(0, ...)` لا `Math.max(1, ...)`.
- عند المجانية لا يظهر حوار «سيُخصم» في `viewer_screen.dart` (`price <= 0`).

## محافظ الزوار: البحث والشحن الجماعي

- البحث في الخادم: `GET /v1/owner/wallets?q=` يطابق `device_id` أو اسم المستخدم
  أو آخر IP (عبر `x_installs`/`x_users`). `GET /v1/owner/users?q=` مطابق LIKE.
- الشحن الجماعي: `POST /v1/owner/wallets/bulk` بجسم `{coins, days, all}`.
  `all:true` = كل المحافظ؛ غيابه يقصر على `q`. التنفيذ `UPDATE ... SELECT` واحد
  (فرعان: بلا `FROM` للكل، وبـ`EXISTS` للبحث) — لا حلقة على الصفوف.
- الشحن إضافة لا تعيين: `balance = balance + ?` — كالشحن الفردي.
- الواجهة في `owner_screen.dart` تبويب المحافظ: زر «شحن للكل» + مربع
  «الكل/نتائج البحث» (`_bulkAll`) + حوار تأكيد يعرض النطاق.

## اختبارات محلية جديدة (worker/)

- `pricing_free_local.test.mjs` — الصفر مجاني، والسعر الموجب يُخصم بالضبط،
  والمالك دائماً مجاني.
- `wallets_bulk_local.test.mjs` — نطاق الشحن (الكل/البحث بالمعرّف/الاسم/IP)،
  والتراكم، والرفض عند صفر عملات أو غياب النطاق.
- `install_kv_resilience_local.test.mjs` — تعذّر KV لا يُسقط `trackDeviceFarm`
  ولا `cached()` ولا `/v1/install`؛ والمكافأة 50 تُمنح مرة واحدة لكل جهاز.
- نمط الاختبار: `stripTypeScriptTypes` + `node:sqlite` في الذاكرة + `vm`،
  وتمرير `context.path`/`context.request` وبدائل الدوال عبر `vm.runInContext`.
  لمسارات المالك، `sealed` يجب أن يُعيد `Response` فعلياً كي يعمل `.json()`.

## بناء APK محلياً (مثبّت ويعمل)

البيئة تبدأ فارغة، وهذا ما ينجح:

```bash
sudo apt-get install -y openjdk-21-jdk-headless unzip zip
# Flutter stable (تحقّق من الإصدار من releases_linux.json قبل التنزيل)
curl -sSL -o /tmp/flutter.tar.xz <flutter_linux_*-stable.tar.xz>
sudo tar -xJf /tmp/flutter.tar.xz -C /opt
# Android cmdline-tools ثم:
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
export ANDROID_HOME=/opt/android-sdk
export PATH=/opt/flutter/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH
yes | sdkmanager --licenses
sdkmanager "platform-tools" "platforms;android-36" "build-tools;36.0.0" "ndk;28.2.13676358"
flutter config --android-sdk /opt/android-sdk --no-analytics
cd app && flutter pub get && flutter build apk --release
# الناتج: app/build/app/outputs/flutter-apk/app-release.apk
```

- Flutter 3.47.6 يطلب: compileSdk/targetSdk=36، minSdk=24، NDK=28.2.13676358.
- AGP 9.1.0 يحتاج JDK 17+ (نجح مع JDK 21) و Gradle 9.3.1 (يُنزَّل تلقائياً).
- `android/app/google-services.json` موجود ومتتبَّع؛ `key.properties` غائب
  فيُوقَّع الإصدار بمفتاح debug (كافٍ للتوزيع اليدوي عبر رابط مباشر).
- لا تستعمل `flutter build` في الخلفية ثم تفقد السجل: راقب `/tmp/apk_build.log`.

## عوائق النشر

- `wrangler deploy` يفشل بـ`R2 binding error ... Please enable R2` عندما يكون
  R2 معطّلاً على الحساب. حتى الـAPI الخام (`PUT /workers/scripts/...`) يرفض
  حزمة فيها أي `r2_bucket` — لا مخرج برمجياً. الحل تفعيل R2 من لوحة Cloudflare.
  الدلو `xapp-releases` مضبوط في `wrangler.toml` ويستضيف `PhoneX-v2.0.2.apk`
  الذي يخدمه `/download/PhoneX.apk`.
- بديل رابط التطبيق حين يتعطّل R2: نشر الـAPK كإصدار GitHub على المستودع
  (عام) — رابط ثابت `releases/latest/download/<file>` يعمل بلا Cloudflare.
  بعد البناء: `gh release create vX.Y.Z app-release.apk --repo <owner>/<repo>`.
  ثم حدّث `updateUrl` في `x_settings` (D1) ليشير إليه حتى لا تتعطّل شاشة
  «حدّث التطبيق» مع تعطّل R2.
- أسرار الـWorker (X_JWT_SECRET، X_OWNER_KEY، FCM_SERVICE_ACCOUNT، ...) تبقى
  في السكربت المنشور عبر `wrangler secret put` ولا تُفقد عند إعادة النشر
  بنفس الاسم.

