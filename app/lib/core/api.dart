import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:http/http.dart' as http;
import 'config.dart';
import 'models.dart';
import 'signer.dart';
import 'store.dart';

/// فك تشفير ردود لوحة المالك.
///
/// المفتاح مشتق من جلسة المالك: SHA-256 على `xapp-owner-panel-v1|<token>`،
/// مطابقاً لحساب الخادم. لا يوجد مفتاح ثابت مضمَّن في التطبيق — أي سرّ
/// مضمَّن يمكن استخراجه من الـAPK، أما جلسة المالك فلا يملكها غيره.
class OwnerCrypto {
  const OwnerCrypto._();

  static Future<cg.SecretKey> _key(String token) async {
    final digest = await cg.Sha256().hash(
        utf8.encode('xapp-owner-panel-v1|$token'));
    return cg.SecretKey(digest.bytes);
  }

  /// يفكّ `nonce.ciphertext` (base64url) ويعيد الخريطة المفكوكة.
  static Future<Map<String, dynamic>> open(
      String token, String sealed) async {
    final dot = sealed.indexOf('.');
    if (dot <= 0) throw const FormatException('sealed payload');
    final nonce = _b64u(sealed.substring(0, dot));
    final blob = _b64u(sealed.substring(dot + 1));
    // WebCrypto يلحق وسم المصادقة (16 بايت) بنهاية النص المشفّر، بينما
    // cryptography يتوقّعه في حقل mac منفصل. تمرير الكتلة كاملة كـ data
    // بوسم فارغ كان يجعل كل ردّ يفشل بالتحقق، فلا تُفكّ أي استجابة في اللوحة.
    if (blob.length <= 16) throw const FormatException('sealed payload');
    final data = blob.sublist(0, blob.length - 16);
    final mac = blob.sublist(blob.length - 16);
    final algo = cg.AesGcm.with256bits();
    final clear = await algo.decrypt(
      cg.SecretBox(data, nonce: nonce, mac: cg.Mac(mac)),
      secretKey: await _key(token),
    );
    return jsonDecode(utf8.decode(clear)) as Map<String, dynamic>;
  }

  static List<int> _b64u(String s) {
    final padded = s.replaceAll('-', '+').replaceAll('_', '/');
    final pad = (4 - padded.length % 4) % 4;
    return base64.decode(padded + '=' * pad);
  }
}

/// إشارة قفل الإصدار — يراها الغلاف فيُبدّل الشاشة فوراً.
///
/// لماذا إشارة عامة لا استثناء فقط؟ لأن الطلب قد يفشل داخل شاشة فرعية
/// (عارض، دردشة، لوحة) وليس في الإقلاع، والقفل يجب أن يسري على التطبيق
/// كله لا على الشاشة التي صادفت الخطأ.
class VersionLock extends ChangeNotifier {
  VersionLock._();
  static final VersionLock instance = VersionLock._();

  String? _message;
  String? get message => _message;
  bool get locked => _message != null;

  static void trigger(String message) {
    final i = instance;
    if (i._message != null) return;
    i._message = message;
    i.notifyListeners();
  }
}

class ApiException implements Exception {
  ApiException(this.status, this.message);
  final int status;
  final String message;
  bool get quotaExhausted => status == 429 || status == 402;
  bool get forbidden => status == 403;

  /// الخادم المنشور لا يعرف نقطة البحث المحصّنة بعد (نسخة قديمة).
  /// تُعرض للمستخدم رسالة مفهومة بدل خطأ عام غامض.
  bool get serverOutdated => status == 404;
  bool get updateRequired => status == 426;
  @override
  String toString() => message;
}

/// عميل HTTP يوقّع كل طلب بمفتاح Ed25519 خاص بالتثبيت ويربطه بالجهاز.
/// لا تُرسل أي طلبات خارج Worker التطبيق.
class Api {
  Api(this.store) : _signer = RequestSigner(store) {
    current = this;
  }
  final Store store;
  final RequestSigner _signer;

  /// آخر عميل أُنشئ — نقطة وصول واحدة لمعالج الدفع.
  static Api? current;

  /// ترويسات توقيع جاهزة — تُستخدم لتحميل الصور الموقّعة (إعلانات المالك).
  ///
  /// تُخزَّن مؤقتاً لأن التوقيع يتضمّن الطابع الزمني، وتوليده في كل بناء يعني
  /// رابطاً جديداً لكل صورة في كل إطار. Flutter يخزّن الصور بمفتاح يشمل
  /// الترويسات، فتغيّرها يُبطل التخزين ويُعيد التنزيل — وهذا سبب ارتجاف
  /// الصور واهتزاز القائمة عند الكتابة أو كل دورة تحديث. ترويسة ثابتة داخل
  /// نافذة الصلاحية تُعيد التخزين إلى العمل.
  final _sigCache = <String, Map<String, String>>{};
  final _sigCacheAt = <String, int>{};

  void clearMediaSignatures() {
    _sigCache.clear();
    _sigCacheAt.clear();
  }

  /// صلاحية ترويسة الوسائط — أقصر من نافذة الخادم (دقيقتان) بهامش أمان
  /// يستوعب فرق ساعة الجهاز، فلا يُرفض رابط ثُبّت لتوّه.
  static const _mediaSigTtlMs = 90 * 1000;

  /// توقيع جاهز لمسار — غير متزامن لأن التوقيع بمفتاح التثبيت.
  ///
  /// التخزين المؤقت ضروري لا تحسيناً: بناء قائمة صور يطلب التوقيع لكل عنصر
  /// في كل إطار، وتوقيع Ed25519 لكل طلب كان يجعل التمرير ثقيلاً.
  Future<Map<String, String>> signFor(String method, String pathWithQuery,
      {List<int>? body}) async {
    // الجلسة جزء من المفتاح: تخزين ترويسة تحمل رمز جلسة قديم بعد تبديل
    // الحساب يعني تحميل وسائط بصلاحية من سجّل خروجه — وهذا خلل أمني لا
    // مجرّد خطأ عرض. تغيّر الرمز يُبطل المفتاح فيُوقَّع من جديد فوراً.
    final key = '${store.ownerToken ?? ''}\u0000${store.token ?? ''}\u0000${store.installId}\u0000$method $pathWithQuery';
    final now = DateTime.now().millisecondsSinceEpoch;
    final cached = _sigCache[key];
    if (cached != null && now - (_sigCacheAt[key] ?? 0) < _mediaSigTtlMs) {
      return cached;
    }
    final fresh = await _sign(method, pathWithQuery, body: body);
    // حدّ أعلى للمفاتيح: كل قسم/صورة مدخل، وقائمة بلا سقف تنمو بلا نهاية
    // في جلسة طويلة. 256 مدخلاً تكفي شاشات مفتوحة فعلياً.
    if (_sigCache.length >= 256) {
      _sigCache.clear();
      _sigCacheAt.clear();
    }
    _sigCache[key] = fresh;
    _sigCacheAt[key] = now;
    return fresh;
  }

  /// التوقيع الفعلي — يفوّض للموقّع ذي المفتاح الخاص بالتثبيت.
  Future<Map<String, String>> _sign(String method, String pathWithQuery,
      {List<int>? body}) async {
    final base = await _signer.headers(method, pathWithQuery, body: body);
    return {
      ...base,
      // جلسة المالك تُقدَّم أولاً: الخادم يميّزها بسرّها المستقل، وبدونها
      // كان المالك يُعامَل كمشترك بلا استحقاق فيُحجب عنه بثّ دوراته المقفلة.
      if (store.ownerToken != null && store.ownerToken!.isNotEmpty)
        'Authorization': 'Bearer ${store.ownerToken}'
      else if (store.token != null)
        'Authorization': 'Bearer ${store.token}',
    };
  }

  /// توقيع طلبات التعلّم. التوقيع الأساسي يعرّف المالك أصلاً (انظر [_sign])،
  /// وهذا الغلاف موجود ليبقى نية طلبات الدورات صريحة في موضع النداء.
  Future<Map<String, String>> _signLearn(String method, String pathWithQuery) =>
      _sign(method, pathWithQuery);

  /// عنوان مطلق لمسار بثّ داخل الخادم. `Uri.parse` مقصود لا `_uri`: رابط
  /// البثّ يحمل استعلاماً موقّعاً (`?i=&e=&s=`)، وبناؤه كـ`path` كان
  /// يُرمّز `?` فيفقد الرمز ويردّ الخادم «رابط غير صالح».
  Uri streamUriFor(String path) => Uri.parse('$kApiBase$path');

  /// ترويسات موقّعة لمسار بثّ.
  ///
  /// التوقيع يحمل طابعاً زمنياً يُرفض بعد 10 دقائق، فلا يصلح ترويسة ثابتة
  /// تُمرَّر للمشغّل مرة واحدة: التشغيل الطويل ينقطع في المنتصف. يستدعي هذا
  /// من الوكيل المحلي عند **كل** طلب قطعة، فيبقى التوقيع صالحاً دائماً.
  Future<Map<String, String>> streamHeadersFor(String path) =>
      _signLearn('GET', path);

  Uri _uri(String path, [Map<String, String>? query]) {
    final base = Uri.parse(kApiBase);
    return Uri(
        scheme: base.scheme,
        host: base.host,
        path: path,
        queryParameters: query);
  }

  Future<Map<String, dynamic>> get(String path,
      {Map<String, String>? query, Duration? timeout}) async {
    final uri = _uri(path, query);
    final pq = uri.path + (uri.hasQuery ? '?${uri.query}' : '');
    final res = await http
        .get(uri, headers: await _sign('GET', pq))
        .timeout(timeout ?? const Duration(seconds: 30));
    return _decode(res);
  }

  Future<Map<String, dynamic>> post(String path, Map<String, dynamic> body,
      {Map<String, String>? query, Duration? timeout}) async {
    final uri = _uri(path, query);
    final pq = uri.path + (uri.hasQuery ? '?${uri.query}' : '');
    final encoded = jsonEncode(body);
    final res = await http
        .post(uri,
            // بصمة الجسم جزء من التوقيع: إرسال الجسم بلا توقيعه يعني رفض
            // الطلب بـ«توقيع غير صالح» على كل POST في التطبيق.
            headers: {
              ...await _sign('POST', pq, body: utf8.encode(encoded)),
              'Content-Type': 'application/json',
            },
            body: encoded)
        .timeout(timeout ?? const Duration(seconds: 30));
    return _decode(res);
  }

  Future<Map<String, dynamic>> put(String path, Map<String, dynamic> body) =>
      _send('PUT', path, body);
  Future<Map<String, dynamic>> delete(String path) => _send('DELETE', path, null);

  Future<Map<String, dynamic>> _send(
      String method, String path, Map<String, dynamic>? body) async {
    final uri = _uri(path);
    final res = await (switch (method) {
      'PUT' => http.put(uri,
          headers: {
            ...await _sign('PUT', uri.path,
                body: body == null ? null : utf8.encode(jsonEncode(body))),
            'Content-Type': 'application/json',
          },
          body: body == null ? null : jsonEncode(body)),
      'DELETE' => http.delete(uri, headers: await _sign('DELETE', uri.path)),
      _ => throw ArgumentError(method),
    }).timeout(const Duration(seconds: 30));
    return _decode(res);
  }

  /// تحميل ملف (PDF/PNG) موقّع ومشفّر — يُفك هنا فقط داخل التطبيق.
  Future<({Uint8List bytes, int quotaLeft, String contentType})> getBytes(
      String path) async {
    final uri = _uri(path);
    final res = await http
        .get(uri, headers: await _sign('GET', uri.path))
        .timeout(const Duration(minutes: 3));
    if (res.statusCode != 200) {
      throw ApiException(res.statusCode, _errMsg(res));
    }
    final bytes = res.bodyBytes;
    final contentType = res.headers['content-type'] ??
        res.headers['x-orig-type'] ??
        'application/octet-stream';
    return (
      bytes: bytes,
      quotaLeft: int.tryParse(res.headers['x-quota-remaining'] ?? '') ?? -1,
      contentType: contentType,
    );
  }

  /// ينزّل بثّ الفيديو على شكل دفق إلى ملف.
  ///
  /// لماذا دفق: فيديو بمئات الميغابايت كان يُجلب كاملاً (`bodyBytes`) ثم
  /// يُكتب. هنا يمرّ من الذاكرة ما يلزم للقطعة الحالية فقط، فيعمل الفيديو
  /// نفسه على جهاز بذاكرة صغيرة.
  ///
  /// لا فكّ تشفير في العميل: كان الملف يُشفَّر بمفتاح مضمَّن في الحزمة
  /// (`FileKey`) ثم يُفكّ هنا. المفتاح كان يُستخرج من الـAPK، فلم يكن يمنع
  /// أحداً. الحماية الفعلية هي TLS + جلسة صالحة + كود المالك، وكلها على
  /// الخادم.
  ///
  /// يعيد: عدد البايتات المكتوبة، ونوع المحتوى الأصلي.
  /// يرمي [ApiException] عند فشل الشبكة أو رفض الخادم.
  Future<({int bytes, String contentType})> downloadCourseVideoToFile(
    String streamPath,
    File target, {
    void Function(int received, int total)? onProgress,
  }) async {
    final uri = _uri(streamPath);
    final client = http.Client();
    File? tmp;
    try {
      final req = http.Request('GET', uri)
        ..headers.addAll(await _signLearn('GET', uri.path));
      final res = await client
          .send(req)
          .timeout(const Duration(minutes: 5));

      if (res.statusCode != 200) {
        final body = await res.stream.bytesToString();
        throw ApiException(res.statusCode,
            _errMsgFromBody(body, res.statusCode));
      }

      final total = int.tryParse(res.headers['content-length'] ?? '') ?? 0;
      final contentType = res.headers['x-orig-type'] ??
          res.headers['content-type'] ??
          'video/mp4';

      // نكتب أولاً إلى ملف جانبي: لو انقطع الاتصال في المنتصف لم يبقَ ملف
      // ناقص يُظنّ لاحقاً أنه فيديو كامل وشغّل نصف مقطع.
      tmp = File('${target.path}.part');
      final sink = tmp.openWrite();
      var received = 0;
      try {
        await for (final chunk in res.stream) {
          received += chunk.length;
          onProgress?.call(received, total);
          sink.add(chunk);
        }
      } finally {
        await sink.flush();
        await sink.close();
      }

      final written = await tmp.length();
      if (written == 0) throw ApiException(500, 'الفيديو فارغ');

      // النقل الذرّي بعد نجاح التنزيل كاملاً.
      if (await target.exists()) await target.delete();
      await tmp.rename(target.path);
      return (bytes: written, contentType: contentType);
    } finally {
      client.close();
      // ملف جانبي متبقٍ بعد فشل: يُنظَّف هنا بلا استثناء.
      if (tmp != null && await tmp.exists()) {
        try {
          await tmp.delete();
        } catch (_) {}
      }
    }
  }


  /// رسالة الخطأ من جسم لم تُفكّ ترميزه بعد — تُستعمل مع الاستجابات المتدفقة.
  String _errMsgFromBody(String body, int status) {
    try {
      final j = jsonDecode(body);
      return j['error']?.toString() ?? 'خطأ $status';
    } catch (_) {
      return 'خطأ في الاتصال ($status)';
    }
  }

  Map<String, dynamic> _decode(http.Response res) {
    if (res.statusCode >= 200 && res.statusCode < 300) {
      try {
        final body = jsonDecode(utf8.decode(res.bodyBytes)) as Map<String, dynamic>;
        return body;
      } catch (_) {
        return {'ok': true};
      }
    }
    // 426 يعني أن المالك أوقف هذا الإصدار أثناء فتح التطبيق. بدون التقاطه
    // هنا يرى المستخدم «خطأ 426» في كل شاشة ويظل يستعمل التطبيق شكلياً،
    // وهو أسوأ من القفل: لا يعرف أن عليه التحديث. الإشارة عامة فتُغلق
    // الواجهة كلها من موضع واحد.
    if (res.statusCode == 426) VersionLock.trigger(_errMsg(res));
    throw ApiException(res.statusCode, _errMsg(res));
  }

  // ===== لوحة المالك: جلسة معزولة وردود مشفّرة =====

  /// جسم الطلب بصيغة البايتات المرسلة فعلاً — للتوقيع.
  static List<int>? _enc(Map<String, dynamic>? body) =>
      body == null ? null : utf8.encode(jsonEncode(body));

  /// ترويسات جلسة المالك — تُستخدم لطلبات اللوحة وحدها.
  Future<Map<String, String>> _ownerSign(String method, String pathWithQuery,
      {List<int>? body}) async {
    final base = await _signer.headers(method, pathWithQuery, body: body);
    return {...base, 'Authorization': 'Bearer ${store.ownerToken}'};
  }

  /// دخول المالك — مسار معزول يعيد جلسة بسرّ مستقل.
  Future<Map<String, dynamic>> ownerLogin(
      String username, String password) async {
    final uri = _uri('/v1/owner/login');
    final payload = jsonEncode({'username': username, 'password': password});
    final res = await http
        .post(uri,
            headers: {
              ...await _sign('POST', uri.path, body: utf8.encode(payload)),
              'Content-Type': 'application/json'
            },
            body: payload)
        .timeout(const Duration(seconds: 30));
    return _decode(res);
  }

  /// يفكّ رد لوحة المالك المشفّر.
  ///
  /// المفتاح مشتق من جلسة المالك نفسها (SHA-256 على وسم ثابت + الرمز)،
  /// مطابقاً لما يفعله الخادم. هذا يعني أن استجابة مسرّبة إلى سجل أو نسخة
  /// احتياطية تبقى غير مقروءة بلا الجلسة.
  Future<Map<String, dynamic>> _ownerDecode(http.Response res) async {
    final body = _decode(res);
    final enc = body['enc'];
    if (enc is! String) return body;
    final token = store.ownerToken;
    if (token == null) throw ApiException(401, 'انتهت جلسة المالك — أعد الدخول');
    try {
      return await OwnerCrypto.open(token, enc);
    } catch (_) {
      throw ApiException(401, 'تعذر فك رد اللوحة — أعد الدخول');
    }
  }

  Future<Map<String, dynamic>> ownerGet(String path,
      {Map<String, String>? query}) async {
    final uri = _uri(path, query);
    final pq = uri.path + (uri.hasQuery ? '?${uri.query}' : '');
    final res = await http
        .get(uri, headers: await _ownerSign('GET', pq))
        .timeout(const Duration(seconds: 30));
    return _ownerDecode(res);
  }

  Future<Map<String, dynamic>> ownerSend(
      String method, String path, Map<String, dynamic>? body) async {
    final uri = _uri(path);
    final res = await (switch (method) {
      'POST' => http.post(uri,
          headers: {
            ...await _ownerSign('POST', uri.path, body: _enc(body)),
            'Content-Type': 'application/json'
          },
          body: body == null ? null : jsonEncode(body)),
      'PUT' => http.put(uri,
          headers: {
            ...await _ownerSign('PUT', uri.path, body: _enc(body)),
            'Content-Type': 'application/json'
          },
          body: body == null ? null : jsonEncode(body)),
      'DELETE' => http.delete(uri, headers: await _ownerSign('DELETE', uri.path)),
      _ => throw ArgumentError(method),
    }).timeout(const Duration(seconds: 30));
    return _ownerDecode(res);
  }

  /// يرسل بايتات خام كجسم للطلب — لأجزاء الفيديو، لا لـJSON.
  ///
  /// مسار `ownerSend` يرمّز الجسم JSON، وهذا يفسد فيديو. هنا الجسم بايتات
  /// كما هي، والتوقيع يشمل المسار نفسه أما أسلوب ما بعد فك الردّ فسليم.
  Future<Map<String, dynamic>> ownerSendRaw(
      String method, String path, List<int> bytes,
      {String contentType = 'application/octet-stream'}) async {
    final uri = _uri(path);
    final headers = {
      ...await _ownerSign(method, uri.path, body: bytes),
      'Content-Type': contentType,
    };
    final res = await (switch (method) {
      'PUT' => http.put(uri, headers: headers, body: bytes),
      'POST' => http.post(uri, headers: headers, body: bytes),
      _ => throw ArgumentError(method),
    }).timeout(const Duration(minutes: 5));
    return _ownerDecode(res);
  }

  String _errMsg(http.Response res) {
    try {
      final j = jsonDecode(utf8.decode(res.bodyBytes));
      return j['error']?.toString() ?? 'خطأ ${res.statusCode}';
    } catch (_) {
      return 'خطأ في الاتصال (${res.statusCode})';
    }
  }

  // ===== واجهات جاهزة =====

  /// مهلة الإقلاع قصيرة عمداً: أول تشغيل على شبكة ضعيفة يجب أن يُظهر زر
  /// إعادة المحاولة بسرعة بدل تدوير 30 ثانية × 5 محاولات.
  static const _bootTimeout = Duration(seconds: 12);

  Future<Map<String, dynamic>> bootstrap() =>
      get('/v1/bootstrap', timeout: _bootTimeout);

  // ===== أكاديمية الدورات =====

  /// قائمة الدورات كما يراها هذا الجهاز.
  ///
  /// الخادم هو من يقرّر ما يُفتح: كل فيديو يحمل `playable`، والمقفل يأتي بلا
  /// رابط بث إطلاقاً، فلا تحتاج الواجهة إلى أي منطق أمني من جهتها.
  Future<({List<Course> courses, String telegramUrl})> courses() async {
    final j = await get('/v1/learn/courses');
    return (
      courses: ((j['courses'] as List?) ?? const [])
          .whereType<Map>()
          .map((e) => Course.fromJson(e.cast<String, dynamic>()))
          .toList(),
      telegramUrl: j['telegramUrl']?.toString() ?? '',
    );
  }

  /// تفعيل مفتاح دورة على هذا الجهاز. يعيد عنوان الدورة للتأكيد.
  Future<Map<String, dynamic>> redeemCourseKey(String code) =>
      post('/v1/learn/redeem', {'code': code});

  Future<void> registerInstall() => post('/v1/install', {
        'installId': store.deviceId,
        'appVersion': '$kAppVersion',
      }, timeout: _bootTimeout);

  Future<Map<String, dynamic>> guest() =>
      post('/v1/auth/guest', {}, timeout: _bootTimeout);

  Future<Map<String, dynamic>> login(String username, String password) =>
      post('/v1/auth/login', {'username': username, 'password': password});

  Future<Map<String, dynamic>> register(
          String username, String password, String displayName, String note) =>
      post('/v1/auth/register', {
        'username': username,
        'password': password,
        'displayName': displayName,
        'note': note,
      });

  Future<Map<String, dynamic>> me() => get('/v1/me', timeout: _bootTimeout);

  /// يهيّئ هوية التوقيع: يولّد زوج المفاتيح ويسجّل العام على الخادم.
  ///
  /// يُستدعى في الإقلاع قبل أي طلب آخر. التسجيل نفسه غير موقّع — لا يمكن
  /// توقيع طلب بمفتاح لم يُسجَّل بعد — وهو الطلب الوحيد المستثنى في الخادم.
  Future<void> initSigningKey() async {
    await _signer.ensureKey((installId, publicKey) async {
      // نداء مباشر بلا توقيع: الموقّع لم يُجهَّز بعد.
      final uri = _uri('/v1/install/key');
      final res = await http
          .post(uri,
              headers: {
                'Content-Type': 'application/json',
                'x-device-id': store.deviceId,
                'x-app-version': '$kAppVersion',
                'User-Agent': 'X-App/$kAppVersionName',
              },
              body: jsonEncode({
                'installId': installId,
                'publicKey': publicKey,
                'appVersion': '$kAppVersion',
              }))
          .timeout(_bootTimeout);
      // 409 يعني أن هذا التثبيت سُجّل بمفتاح آخر (أُعيد ضبط البيانات مع
      // بقاء المعرّف). لا يُحلّ بصمت: نرمي ليُعاد التوليد بمعرّف جديد في
      // الإقلاع التالي بدل أن يبقى التطبيق بلا توقيع صالح.
      if (res.statusCode != 200) {
        throw ApiException(res.statusCode, _errMsg(res));
      }
    });
  }

  /// المطالبة بهدية الحصة اليومية.
  ///
  /// المبلغ يحدده الخادم من إعدادات المالك ولا يُرسل من هنا، والمنح مرة
  /// واحدة في اليوم لكل محفظة — فالخادم يرد 409 إن سبق الاستلام.
  Future<Map<String, dynamic>> claimGift() => post('/v1/gift/claim', {});

  Future<List<dynamic>> compatBrands() async =>
      (await get('/v1/data/brands'))['brands'] as List;

  /// دخول شركة: هنا يقع الخصم الوحيد (مرة لكل شركة في اليوم).
  /// يُستدعى عند فتح شاشة الشركة، فيرى المستخدم رصيده قبل أن يكتب أي حرف.
  Future<CompatOpenResult> openCompat(String? brand) async {
    final j = await post('/v1/data/compat/open',
        {'brand': brand ?? ''}, timeout: const Duration(seconds: 20));
    return CompatOpenResult(
      charged: j['charged'] == true,
      remaining: (j['remaining'] as num?)?.toInt() ?? -1,
      balance: (j['balance'] as num?)?.toInt() ?? -1,
      source: '${j['source'] ?? ''}',
    );
  }

  /// بحث التوافقات — يتم على الخادم داخل نطاق الشركة والنوع.
  /// لا نجلب ملف الشركة كاملاً بعد الآن: كان ذلك ~65KB و0.9 ثانية لكل دخول،
  /// وهو ما كان يسبب إحساس «تحميل كل التوافقات»، وكان يسمح بسحب البيانات.
  /// ولا يخصم: الخصم وقع عند دخول الشركة (openCompat).
  Future<CompatSearchResult> searchCompatCharged(String q,
      {String? brand, String? type}) async {
    final body = <String, dynamic>{'q': q};
    if (brand != null && brand.isNotEmpty) body['brand'] = brand;
    if (type != null && type.isNotEmpty) body['type'] = type;
    final j = await post('/v1/data/compat/search', body);
    return CompatSearchResult(
      records: (j['records'] as List?) ?? const [],
      types: ((j['types'] as List?) ?? const []).map((e) => '$e').toList(),
      charged: j['charged'] == true,
      remaining: (j['remaining'] as num?)?.toInt() ?? -1,
      balance: (j['balance'] as num?)?.toInt() ?? -1,
      source: '${j['source'] ?? ''}',
    );
  }

  Future<List<dynamic>> searchCompat(String q,
      {String? brand, String? type}) async {
    final r = await searchCompatCharged(q, brand: brand, type: type);
    return r.records;
  }

  /// كل سجلات شركة واحدة — حُذفت: القراءة الكاملة صارت مرفوضة على الخادم
  /// (استعلام فارغ = 400) لأنها كانت تسمح بسحب كل التوافقات مجاناً.

  Future<List<dynamic>> schemBrands() async =>
      (await get('/v1/schem/brands'))['brands'] as List;

  Future<List<dynamic>> schemModels(String brandId, {String q = ''}) async =>
      (await get('/v1/schem/brands/${Uri.encodeComponent(brandId)}/models',
          query: q.isEmpty ? null : {'q': q}))['models'] as List;

  Future<List<dynamic>> schemFiles(String folderId) async =>
      (await get(
              '/v1/schem/folders/${Uri.encodeComponent(folderId)}/files'))['files']
          as List;

  // ===== المالك =====
  /// يسحب وسم «جهاز المالك» عن هذا التثبيت قبل إنهاء الجلسة.
  ///
  /// بدونه يبقى `ownerDevice` صادقاً في الخادم فيرى هذا الجهاز كل دورة
  /// مقفلة مفتوحةً حتى بعد خروج المالك — وهو بالضبط خلل «الدورات تبقى
  /// مفتوحة بعد الخروج». الفشل هنا لا يمنع الخروج المحلي.
  Future<void> ownerReleaseDevice() =>
      ownerSend('POST', '/v1/owner/device/release', {}).then((_) {});

  Future<Map<String, dynamic>> ownerOverview() => ownerGet('/v1/owner/overview');
  Future<Map<String, dynamic>> ownerSettings() => ownerGet('/v1/owner/settings');
  Future<Map<String, dynamic>> saveSettings(Map<String, dynamic> s) =>
      ownerSend('PUT', '/v1/owner/settings', s);
  Future<List<dynamic>> ownerUsers({String? q}) async =>
      (await ownerGet('/v1/owner/users',
              query: (q != null && q.trim().isNotEmpty) ? {'q': q.trim()} : null))['users']
          as List;
  Future<List<dynamic>> ownerRequests() async =>
      (await ownerGet('/v1/owner/requests'))['requests'] as List;
  /// سجل الأمان — الهجمات فقط افتراضياً، و`all` يكشف كل الأحداث.
  Future<List<dynamic>> ownerSecurity({bool all = false}) async =>
      (await ownerGet('/v1/owner/security', query: all ? {'all': '1'} : null))['events']
          as List;
  Future<void> userAction(String id, String action, {int? days}) =>
      ownerSend('POST', '/v1/owner/users/$id/$action', {if (days != null) 'days': days});
  Future<void> requestAction(String id, String action) =>
      ownerSend('POST', '/v1/owner/requests/$id/$action', {});
  Future<void> createUser(
          String username, String password, String displayName, int days,
          {int cards = 0, int cardDays = 0}) =>
      ownerSend('POST', '/v1/owner/users', {
        'username': username,
        'password': password,
        'displayName': displayName,
        'days': days,
        'cards': cards,
        'cardDays': cardDays,
      });

  /// شحن بطاقات مخططات لمستخدم — يضيف للرصيد ويحدد الصلاحية
  Future<void> grantQuota(String id, int cards, int days) =>
      ownerSend('POST', '/v1/owner/users/$id/quota', {'cards': cards, 'days': days});

  /// محافظ الزوار: عملات لزائر بلا حساب، مفتاحها معرّف الجهاز.
  /// البحث في الخادم (المعرّف/الاسم/آخر IP) لا في العميل.
  Future<List<dynamic>> ownerWallets({String? q}) async =>
      (await ownerGet('/v1/owner/wallets',
              query: (q != null && q.trim().isNotEmpty) ? {'q': q.trim()} : null))['wallets']
          as List;
  Future<void> grantWallet(String deviceId, int coins, int days) =>
      ownerSend('POST', '/v1/owner/wallets', {
        'deviceId': deviceId,
        'coins': coins,
        'days': days,
      });

  /// شحن جماعي: يضيف عملات لكل المحافظ. `all: true` يشمل الكل، وإلا
  /// يقصر الشحن على نتائج البحث `q`. يعيد عدد المحافظ التي تغيّرت.
  Future<int> grantWalletBulk(int coins, int days,
      {bool all = false, String? q}) async {
    final r = await ownerSend('POST', '/v1/owner/wallets/bulk', {
      'coins': coins,
      'days': days,
      'all': all,
      if (q != null && q.trim().isNotEmpty) 'q': q.trim(),
    });
    return (r['affected'] as num?)?.toInt() ?? 0;
  }

  /// تعديل محفظة: تعيين الرصيد والصلاحية إلى قيم محددة.
  Future<void> editWallet(String deviceId, int coins, int days) =>
      ownerSend('PUT', '/v1/owner/wallets', {
        'deviceId': deviceId,
        'coins': coins,
        'days': days,
      });

  /// إنقاص أو إضافة بجرعة (delta سالب للإنقاص).
  Future<Map<String, dynamic>> adjustWallet(String deviceId, int delta,
          {int days = 0}) =>
      ownerSend('POST', '/v1/owner/wallets/adjust', {
        'deviceId': deviceId,
        'delta': delta,
        'days': days,
      });

  /// حذف محفظة بالكامل.
  Future<void> deleteWallet(String deviceId) => ownerSend(
      'DELETE', '/v1/owner/wallets/${Uri.encodeComponent(deviceId)}', null);

  /// حذف سجلات الأمان. بلا وسائط يمسح الكل؛ `reason` يمسح نوعاً واحداً.
  Future<int> clearSecurityLogs({String? reason, int? beforeMs}) async {
    final q = <String>[
      if (reason != null && reason.isNotEmpty) 'reason=${Uri.encodeComponent(reason)}',
      if (beforeMs != null && beforeMs > 0) 'before=$beforeMs',
    ];
    final r = await ownerSend(
        'DELETE',
        '/v1/owner/security${q.isEmpty ? '' : '?${q.join('&')}'}',
        null);
    return (r['deleted'] as num?)?.toInt() ?? 0;
  }
  Future<List<dynamic>> ownerBans() async =>
      (await ownerGet('/v1/owner/bans'))['bans'] as List;
  Future<void> banDevice(String deviceId, String reason) =>
      ownerSend('POST', '/v1/owner/bans', {'deviceId': deviceId, 'reason': reason});

  /// حظر عنوان IP — يمنع المهاجم حتى لو غيّر جهازه.
  Future<void> banIp(String ip, String reason) =>
      ownerSend('POST', '/v1/owner/bans', {'ip': ip, 'reason': reason});
  Future<void> unbanDevice(String deviceId) => ownerSend(
      'DELETE', '/v1/owner/bans/${Uri.encodeComponent(deviceId)}', null);
  Future<List<dynamic>> ownerAnnouncements() async =>
      (await ownerGet('/v1/owner/announcements'))['announcements'] as List;
  Future<Map<String, dynamic>> createAnnouncement(
          String title, String subtitle, String linkUrl,
          {String? imageB64, String? imageExt, String? imageUrl}) =>
      ownerSend('POST', '/v1/owner/announcements', {
        'title': title,
        'subtitle': subtitle,
        'linkUrl': linkUrl,
        if (imageB64 != null) 'imageB64': imageB64,
        if (imageExt != null) 'imageExt': imageExt,
        if (imageUrl != null) 'imageUrl': imageUrl,
      });
  Future<void> deleteAnnouncement(String id) =>
      ownerSend('DELETE', '/v1/owner/announcements/$id', null);

  // ===== الدردشة =====

  Future<ChatState> chatState() async =>
      ChatState.fromJson(await get('/v1/chat/state'));

  /// رسائل قسم.
  ///
  /// ثلاثة أنماط، وكلها محدودة:
  ///   [since]  الجديد بعد ختم زمني — يُستدعى كل بضع ثوانٍ، وعادةً يعود فارغاً.
  ///   [before] دفعة أقدم عند التمرير للأعلى.
  ///   بلا شيء  أحدث صفحة عند أول فتح.
  /// هذا ما يمنع تحميل المحادثة كاملة كل مرة، فلا تثقل الشبكة ولا الذاكرة.
  Future<ChatPage> chatMessages(
    String room, {
    int since = 0,
    int before = 0,
    int limit = 40,
  }) async {
    final j = await get('/v1/chat/messages', query: {
      'room': room,
      if (since > 0) 'since': '$since',
      if (before > 0) 'before': '$before',
      'limit': '$limit',
    });
    return ChatPage(
      messages: ((j['messages'] as List?) ?? const [])
          .whereType<Map>()
          .map((e) => ChatMessage.fromJson(e.cast<String, dynamic>()))
          .toList(),
      hasMore: j['hasMore'] == true,
      members: (j['members'] as num?)?.toInt(),
      online: (j['online'] as num?)?.toInt(),
    );
  }

  /// يحذف رسالة — صاحبها فقط، أو المالك على أي رسالة.
  ///
  /// الحذف على الخادم لا محلياً: لو حذفناها من القائمة وحدها لعادت في أول
  /// تحديث دوري، فيبدو الحذف كأنه لم يحدث.
  Future<void> chatDelete(String id) async {
    await post('/v1/chat/delete', {'id': id});
  }

  /// إعلام الخادم أن المستخدم بلغ آخر رسالة — أساس «من رأى الرسالة».
  Future<void> chatSeen(String room, int at) =>
      post('/v1/chat/seen', {'room': room, 'at': at});

  /// إرسال رسالة. [mediaB64] صورة أو مقطع، و[mediaSeconds] مدة المقطع.
  Future<ChatMessage> chatSend(
    String room, {
    String text = '',
    String? mediaB64,
    int mediaSeconds = 0,
    List<double> waveform = const [],
    String replyTo = '',
  }) async {
    final j = await post(
      '/v1/chat/send',
      {
        'room': room,
        'text': text,
        if (mediaB64 != null) 'mediaB64': mediaB64,
        if (mediaSeconds > 0) 'mediaSeconds': mediaSeconds,
        if (waveform.isNotEmpty) 'waveform': waveform,
        if (replyTo.isNotEmpty) 'replyTo': replyTo,
      },
      // رفع مقطع يحتاج مهلة أطول من رسالة نصية.
      timeout: mediaB64 == null
          ? const Duration(seconds: 30)
          : const Duration(minutes: 3),
    );
    return ChatMessage.fromJson(
        (j['message'] as Map?)?.cast<String, dynamic>() ?? const {});
  }

  /// يبدأ جلسة رفع مقطع دردشة، ثم يدفع الأجزاء ويُكملها.
  ///
  /// لماذا على أجزاء بدل `chatSend`؟ لأن `chatSend` يحمل الوسيط base64
  /// داخل JSON: حشو يضخّم الحجم 4/3، واحتفاظ بالملف كاملاً في الذاكرة،
  /// فينهي العامل عند مقاطع عشرات الميغابايت. هنا يُقرأ الملف من القرص
  /// جزءاً جزءاً ويُدفَع كما هو — لا حشو ولا تحميل كامل.
  Future<ChatMessage> chatUploadVideo({
    required String room,
    required String filePath,
    String kind = 'video',
    String text = '',
    int seconds = 0,
    String replyTo = '',
    void Function(int sent, int total)? onProgress,
  }) async {
    final file = File(filePath);
    final length = await file.length();
    if (length == 0) throw ApiException(400, 'الملف فارغ');
    final name = filePath.split('/').last;

    final init = await post('/v1/chat/upload/init', {
      'room': room,
      'kind': kind,
      'name': name,
      'mime': _videoMime(name, audio: kind == 'audio'),
      'size': length,
      'seconds': seconds,
      if (text.isNotEmpty) 'text': text,
      if (replyTo.isNotEmpty) 'replyTo': replyTo,
    }, timeout: const Duration(seconds: 60));
    final uploadId = init['uploadId'] as String? ?? '';
    if (uploadId.isEmpty) throw ApiException(500, 'تعذر بدء الرفع');
    // 8MiB يطابق `CHAT_UPLOAD_CHUNK` في العامل. القيمة الاحتياطية هنا
    // لا تنزل عن 5MiB أبداً: R2 يرفض كل جزء أصغر منها (آخر جزء وحده مستثنى)،
    // فخطأ في قيمة واحدة كان يمنع رفع أي فيديو فوق جزء واحد.
    final chunk = (init['chunk'] as num?)?.toInt() ?? 8 * 1024 * 1024;

    final parts = <Map<String, dynamic>>[];
    var sent = 0;
    var partNo = 1;
    try {
      while (sent < length) {
        final end = (sent + chunk < length) ? sent + chunk : length;
        final bytes = await file
            .openRead(sent, end)
            .fold<List<int>>(<int>[], (acc, b) => acc..addAll(b));
        final res = await _putRaw(
            '/v1/chat/upload/$uploadId/part/$partNo', bytes,
            timeout: const Duration(minutes: 5));
        parts.add({'partNumber': partNo, 'etag': res['etag']});
        sent = end;
        onProgress?.call(sent, length);
        partNo++;
      }
      final done = await post(
          '/v1/chat/upload/complete', {'uploadId': uploadId, 'parts': parts},
          timeout: const Duration(minutes: 2));
      return ChatMessage.fromJson(
          (done['message'] as Map?)?.cast<String, dynamic>() ?? const {});
    } catch (e) {
      // لا نترك أجزاء معلّقة في R2 بلا كائن يُشار إليها.
      try {
        await post('/v1/chat/upload/abort', {'uploadId': uploadId},
            timeout: const Duration(seconds: 20));
      } catch (_) {}
      rethrow;
    }
  }

  /// طلب PUT بجسم خام (بايتات ملف) مع ترويسات التطبيق الموقّعة.
  ///
  /// مسار `_send` يرمّز الجسم JSON وهذا يفسد مقطع فيديو، فالجسم هنا بايتات
  /// كما هي. التوقيع يشمل المسار وحده كبقية المسارات.
  Future<Map<String, dynamic>> _putRaw(
    String path,
    List<int> body, {
    Duration timeout = const Duration(minutes: 2),
  }) async {
    final uri = _uri(path);
    final res = await http
        .put(uri,
            headers: {
              ...await _sign('PUT', uri.path, body: body),
              'Content-Type': 'application/octet-stream',
            },
            body: body)
        .timeout(timeout);
    final decoded = res.bodyBytes.isEmpty
        ? <String, dynamic>{}
        : (jsonDecode(utf8.decode(res.bodyBytes, allowMalformed: true)) as Map)
            .cast<String, dynamic>();
    if (res.statusCode >= 400) {
      throw ApiException(res.statusCode,
          decoded['error']?.toString() ?? 'فشل الرفع (${res.statusCode})');
    }
    return decoded;
  }

  /// حفظ ملف الدردشة: كنية، صورة شخصية، وكتم الإشعارات.
  Future<Map<String, dynamic>> chatProfile({
    String? nickname,
    String? imageB64,
    bool clearAvatar = false,
    bool? notify,
  }) =>
      put('/v1/chat/profile', {
        if (nickname != null) 'nickname': nickname,
        if (imageB64 != null) 'imageB64': imageB64,
        if (clearAvatar) 'clearAvatar': true,
        if (notify != null) 'notify': notify,
      });

  // ===== إشراف المالك على الدردشة =====

  Future<List<dynamic>> ownerChatMessages({String room = ''}) async =>
      (await ownerGet('/v1/owner/chat/messages',
              query: room.isEmpty ? null : {'room': room}))['messages']
          as List;

  Future<void> ownerDeleteChatMessage(String id) =>
      ownerSend('DELETE', '/v1/owner/chat/messages/$id', null);

  Future<void> ownerPurgeRoom(String room) =>
      ownerSend('POST', '/v1/owner/chat/purge', {'room': room});

  /// كتم أو طرد عضو. [room] فارغ = كل الأقسام، و[minutes] 0 للكتم الدائم.
  Future<void> ownerChatAction({
    required String userId,
    required String kind,
    String room = '',
    String reason = '',
    int minutes = 0,
  }) =>
      ownerSend('POST', '/v1/owner/chat/action', {
        'userId': userId,
        'kind': kind,
        'room': room,
        'reason': reason,
        'minutes': minutes,
      });

  Future<void> ownerClearChatAction(String userId, {String kind = ''}) =>
      ownerSend('POST', '/v1/owner/chat/action/clear', {
        'userId': userId,
        if (kind.isNotEmpty) 'kind': kind,
      });

  Future<List<ChatAction>> ownerChatActions() async =>
      ((await ownerGet('/v1/owner/chat/actions'))['actions'] as List? ?? const [])
          .whereType<Map>()
          .map((e) => ChatAction.fromJson(e.cast<String, dynamic>()))
          .toList();

  // ===== لوحة المالك: إدارة الدورات =====

  /// كل بيانات الأكاديمية للمالك: الدورات، المفاتيح، والمشتركون.
  Future<Map<String, dynamic>> ownerCourses() =>
      ownerGet('/v1/owner/learn/courses');

  Future<Map<String, dynamic>> ownerSaveCourse({
    String id = '',
    required String title,
    String subtitle = '',
    String description = '',
    bool locked = true,
    int sort = 0,
    bool published = true,
  }) =>
      ownerSend('POST', '/v1/owner/learn/course', {
        'id': id,
        'title': title,
        'subtitle': subtitle,
        'description': description,
        'locked': locked,
        'sort': sort,
        'published': published,
      });

  Future<void> ownerDeleteCourse(String id) =>
      ownerSend('DELETE', '/v1/owner/learn/course/$id', null);

  Future<Map<String, dynamic>> ownerSaveVideo({
    String id = '',
    required String courseId,
    required String title,
    required String objectKey,
    String description = '',
    String mime = 'video/mp4',
    int durationS = 0,
    int sizeBytes = 0,
    String mode = 'locked',
    int sort = 0,
    bool published = true,
  }) =>
      ownerSend('POST', '/v1/owner/learn/video', {
        'id': id,
        'courseId': courseId,
        'title': title,
        'objectKey': objectKey,
        'description': description,
        'mime': mime,
        'durationS': durationS,
        'sizeBytes': sizeBytes,
        'mode': mode,
        'sort': sort,
        'published': published,
      });

  Future<void> ownerDeleteVideo(String id) =>
      ownerSend('DELETE', '/v1/owner/learn/video/$id', null);

  /// يولّد كوداً لدورة. الكود الصريح يعود في هذا الرد وحده ولا يُخزَّن،
  /// فيجب عرضه للمالك فوراً لينسخه ويرسله للمشترك.
  Future<Map<String, dynamic>> ownerCreateCourseKey({
    required String courseId,
    String label = '',
    int maxUses = 1,
    int days = 0,
  }) =>
      ownerSend('POST', '/v1/owner/learn/key', {
        'courseId': courseId,
        'label': label,
        'maxUses': maxUses,
        'days': days,
      });

  Future<void> ownerRevokeCourseKey(String id) =>
      ownerSend('DELETE', '/v1/owner/learn/key/$id', null);

  /// يسحب تمكين مشترك — ينقطع وصوله فوراً بلا أي إجراء على جهازه.
  ///
  /// `installId` هو ما يحكم المنحة فعلاً. `deviceId` يبقى احتياطاً للنسخ
  /// القديمة من اللوحة، لكن الاعتماد عليه وحده كان يُبلّغ بنجاح بلا حذف.
  Future<void> ownerRevokeCourseGrant(String installId, String courseId,
          {String deviceId = ''}) =>
      ownerSend('POST', '/v1/owner/learn/revoke', {
        if (installId.isNotEmpty) 'installId': installId,
        if (deviceId.isNotEmpty) 'deviceId': deviceId,
        'courseId': courseId,
      });

  Future<Map<String, dynamic>> ownerUploadCourseCover(
          String courseId, String dataB64, String mime) =>
      ownerSend('POST', '/v1/owner/learn/cover',
          {'courseId': courseId, 'dataB64': dataB64, 'mime': mime});

  /// مصغّرة الدرس. تُرفع منفصلة عن الفيديو حتى يستطيع المالك استبدال الصورة
  /// وحدها بلا إعادة رفع المقطع — وسيط الملف قد يكون مئات الميغابايت.
  Future<Map<String, dynamic>> ownerUploadCourseThumb(
          String videoId, String dataB64, String mime) =>
      ownerSend('POST', '/v1/owner/learn/thumb',
          {'videoId': videoId, 'dataB64': dataB64, 'mime': mime});

  /// يرفع ملف فيديو إلى دلو الدورات على أجزاء.
  ///
  /// لماذا الأجزاء: Cloudflare يرد 413 على أي طلب يتجاوز 100MB على حافة
  /// الشبكة قبل أن يصل إلى الـWorker، فلا يفيد رفع الملف كاملاً في طلب واحد.
  /// كل جزء هنا 8MB، وطلب واحد لا يتجاوزها أبداً.
  ///
  /// الأجزاء تُرفع تباعاً لا معاً: شبكة الجوال لا تحتمل صعود خمسة عشر طلباً
  /// متزامناً، والترتيب يجعل شريط التقدم صادقاً بدل أن يقفز.
  ///
  /// و`onProgress` تُنادى بعد كل جزء ليُظهر المالك أين وصل الرفع فعلاً.
  Future<Map<String, dynamic>> ownerUploadCourseVideo({
    required String courseId,
    required String title,
    required String filePath,
    String description = '',
    String mode = 'locked',
    void Function(int sent, int total)? onProgress,
  }) async {
    final name = filePath.split('/').last;
    final file = File(filePath);
    final length = await file.length();
    if (length == 0) throw ApiException(400, 'الملف فارغ');

    // 8MB للجزء: صغير بما يكفي ليبقى تحت حدّ الحافة بهامش مريح حتى مع
    // ترويسات الطلب، وكبير بما يكفي ألا يصير فيديو ساعة آلاف الطلبات.
    const chunk = 8 * 1024 * 1024;

    final init = await ownerSend('POST', '/v1/owner/learn/upload/init', {
      'courseId': courseId,
      'title': title,
      'description': description,
      'mode': mode,
      'name': name,
      'mime': _videoMime(name),
      'size': length,
    });
    final uploadId = init['uploadId'] as String;

    final parts = <Map<String, dynamic>>[];
    var sent = 0;
    var partNo = 1;
    try {
      while (sent < length) {
        final end = (sent + chunk < length) ? sent + chunk : length;
        final bytes = await file.openRead(sent, end).fold<List<int>>(
          <int>[], (acc, b) => acc..addAll(b));
        final res = await ownerSendRaw(
            'PUT', '/v1/owner/learn/upload/$uploadId/part/$partNo', bytes,
            contentType: 'application/octet-stream');
        parts.add({'partNumber': partNo, 'etag': res['etag']});
        sent = end;
        onProgress?.call(sent, length);
        partNo++;
      }
      return await ownerSend('POST', '/v1/owner/learn/upload/complete',
          {'uploadId': uploadId, 'parts': parts});
    } catch (e) {
      // لا نترك أجزاءً معلّقة في R2 تستهلك مساحة بلا كائن يُشار إليه.
      try {
        await ownerSend('POST', '/v1/owner/learn/upload/abort', {'uploadId': uploadId});
      } catch (_) {}
      rethrow;
    }
  }

  /// نوع المحتوى من الامتداد — الخادم يقرأه فيخزّنه مع الملف.
  static String _videoMime(String name, {bool audio = false}) {
    final n = name.toLowerCase();
    if (audio) {
      if (n.endsWith('.m4a')) return 'audio/mp4';
      if (n.endsWith('.aac')) return 'audio/aac';
      if (n.endsWith('.mp3')) return 'audio/mpeg';
      if (n.endsWith('.ogg') || n.endsWith('.opus')) return 'audio/ogg';
      return 'audio/mp4';
    }
    if (n.endsWith('.webm')) return 'video/webm';
    if (n.endsWith('.mov')) return 'video/quicktime';
    if (n.endsWith('.mkv')) return 'video/x-matroska';
    if (n.endsWith('.m4v')) return 'video/x-m4v';
    return 'video/mp4';
  }

  // ---------- تحرير التوافقات (للمالك) ----------

  /// الشركات المتاحة للتحرير وأنواع القطع المعروفة.
  Future<Map<String, dynamic>> ownerCompatBrands() =>
      ownerGet('/v1/owner/compat/brands');

  /// سجلات شركة بعد تطبيق تعديلات المالك، مع الأنواع المتوفرة فيها.
  Future<Map<String, dynamic>> ownerCompatList({
    required String brand,
    String? q,
    String? type,
  }) =>
      ownerGet('/v1/owner/compat/list', query: {
        'brand': brand,
        if (q != null && q.trim().isNotEmpty) 'q': q.trim(),
        if (type != null && type.isNotEmpty) 'type': type,
      });

  /// يعدّل صفّاً قائماً. `fields` تُدمج مع أي تعديل سابق لا تستبدله.
  Future<Map<String, dynamic>> ownerCompatPatch({
    required String brand,
    required String id,
    required Map<String, dynamic> fields,
  }) =>
      ownerSend('POST', '/v1/owner/compat/edit',
          {'op': 'patch', 'brand': brand, 'id': id, 'fields': fields});

  /// يُضيف صفوفاً متعدّدة في نداء واحد — إمّا كلها أو لا شيء.
  Future<Map<String, dynamic>> ownerCompatAdd({
    required String brand,
    required List<Map<String, dynamic>> rows,
  }) =>
      ownerSend('POST', '/v1/owner/compat/edit',
          {'op': 'add', 'brand': brand, 'rows': rows});

  /// يحذف صفّاً (المصدر لا يُمسّ، الحذف قابل للاسترجاع).
  Future<Map<String, dynamic>> ownerCompatDelete({
    required String brand,
    required String id,
  }) =>
      ownerSend('POST', '/v1/owner/compat/edit',
          {'op': 'delete', 'brand': brand, 'id': id});

  /// يُضيف نوع قطعة جديداً للشركة.
  Future<Map<String, dynamic>> ownerCompatAddType({
    required String brand,
    required String name,
  }) =>
      ownerSend('POST', '/v1/owner/compat/edit',
          {'op': 'addType', 'brand': brand, 'name': name});
}
