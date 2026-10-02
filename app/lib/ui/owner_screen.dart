import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:image_picker/image_picker.dart';
import '../core/version_rules.dart';
import '../core/api.dart';
import '../core/app_config.dart';
import '../core/config.dart';
import '../core/models.dart';
import '../core/store.dart';
import 'theme.dart';
import 'biometric_gate.dart';
import 'brand_logo.dart';
import 'cached_image.dart';
import 'splash.dart';

/// نسخ معرّف الجهاز — يُستخدم من عدة تبويبات في لوحة المالك.
Future<void> copyDeviceId(BuildContext context, String value) async {
  await Clipboard.setData(ClipboardData(text: value));
  if (!context.mounted) return;
  ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('تم نسخ معرّف الجهاز')));
}

/// لوحة تحكم المالك — تظهر فقط لحساب role=owner
/// التحكم: حصة الزائر، الإصدارات، المستخدمون، الطلبات، سجل الأمان، الإعلانات
class OwnerScreen extends StatefulWidget {
  const OwnerScreen({super.key, required this.api, required this.store});
  final Api api;
  final Store store;

  @override
  State<OwnerScreen> createState() => _OwnerScreenState();
}

class _OwnerScreenState extends State<OwnerScreen> {
  @override
  Widget build(BuildContext context) {
    return DefaultTabController(
      length: 9,
      child: Scaffold(
        appBar: AppBar(
          title: const Text('لوحة تحكم المالك'),
          bottom: TabBar(
            isScrollable: true,
            indicatorColor: XTheme.cyan,
            labelStyle:
                TextStyle(fontWeight: FontWeight.w800, fontSize: 12.5),
            tabs: [
              Tab(text: 'عام', icon: Icon(Icons.analytics_outlined, size: 18)),
              Tab(text: 'الإعدادات', icon: Icon(Icons.tune, size: 18)),
              Tab(text: 'المستخدمون', icon: Icon(Icons.people_outline, size: 18)),
              Tab(text: 'محافظ الزوار', icon: Icon(Icons.account_balance_wallet_outlined, size: 18)),
              Tab(text: 'الإعلانات', icon: Icon(Icons.campaign_outlined, size: 18)),
              Tab(text: 'الدردشة', icon: Icon(Icons.forum_outlined, size: 18)),
              Tab(text: 'الدورات', icon: Icon(Icons.play_lesson_outlined, size: 18)),
              Tab(text: 'الحظر', icon: Icon(Icons.gpp_bad_outlined, size: 18)),
              Tab(text: 'الأمان', icon: Icon(Icons.security, size: 18)),
            ],
          ),
        ),
        body: TabBarView(children: [
          _OverviewTab(api: widget.api),
          _SettingsTab(api: widget.api, store: widget.store),
          _UsersTab(api: widget.api),
          _WalletsTab(api: widget.api),
          _AnnouncementsTab(api: widget.api),
          _ChatTab(api: widget.api),
          _CoursesTab(api: widget.api),
          _BansTab(api: widget.api),
          _SecurityTab(api: widget.api),
        ]),
      ),
    );
  }
}

// ============ نظرة عامة ============

class _OverviewTab extends StatefulWidget {
  const _OverviewTab({required this.api});
  final Api api;
  @override
  State<_OverviewTab> createState() => _OverviewTabState();
}

class _OverviewTabState extends State<_OverviewTab> {
  Map<String, dynamic>? _data;
  List<dynamic> _requests = [];

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final d = await widget.api.ownerOverview();
      final r = await widget.api.ownerRequests();
      if (mounted) {
        setState(() {
          _data = d;
          _requests = r;
        });
      }
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    if (_data == null) {
      return Center(
          child: CircularProgressIndicator(color: XTheme.accent));
    }
    final d = _data!;
    return RefreshIndicator(
      onRefresh: _load,
      color: XTheme.accent,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          GridView.count(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            crossAxisCount: 2,
            mainAxisSpacing: 12,
            crossAxisSpacing: 12,
            childAspectRatio: 1.55,
            children: [
              _stat('التثبيتات', '${d['installs']}', Icons.download_rounded,
                  XTheme.accent),
              _stat('المستخدمون', '${d['users']}', Icons.people_alt_outlined,
                  XTheme.cyan),
              _stat('طلبات معلّقة', '${d['pendingRequests']}',
                  Icons.pending_actions, XTheme.gold),
              _stat('أحداث أمنية (24س)', '${d['securityEvents24h']}',
                  Icons.shield_outlined, XTheme.danger),
            ],
          ),
          const SizedBox(height: 16),
          if ((d['installsByVersion'] as List?)?.isNotEmpty == true) ...[
            const Text('التثبيتات حسب الإصدار',
                style: TextStyle(fontWeight: FontWeight.w800, fontSize: 15)),
            const SizedBox(height: 8),
            ...(d['installsByVersion'] as List).map((v) => Padding(
                  padding: const EdgeInsets.only(bottom: 6),
                  child: GlassCard(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 14, vertical: 10),
                    child: Row(children: [
                      Icon(Icons.phone_android,
                          size: 18, color: XTheme.textDim),
                      const SizedBox(width: 10),
                      Expanded(child: Text('إصدار ${v['v']}')),
                      Text('${v['c']}',
                          style: TextStyle(
                              fontWeight: FontWeight.w900,
                              color: XTheme.cyan)),
                    ]),
                  ),
                )),
          ],
          const SizedBox(height: 16),
          if (_requests.isNotEmpty) ...[
            const Text('طلبات إنشاء الحسابات',
                style: TextStyle(fontWeight: FontWeight.w800, fontSize: 15)),
            const SizedBox(height: 8),
            ..._requests.where((r) => r['status'] == 'pending').map((r) =>
                Padding(
                  padding: const EdgeInsets.only(bottom: 8),
                  child: GlassCard(
                    padding: const EdgeInsets.all(14),
                    child: Row(children: [
                      Icon(Icons.person_add_alt,
                          color: XTheme.gold, size: 22),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(r['username'] ?? '',
                                  style: const TextStyle(
                                      fontWeight: FontWeight.w800)),
                              if ((r['note'] ?? '').toString().isNotEmpty)
                                Text(r['note'],
                                    style: TextStyle(
                                        color: XTheme.textDim, fontSize: 12)),
                              Text('جهاز: ${r['device_id'] ?? '—'}',
                                  style: TextStyle(
                                      color: XTheme.textDim, fontSize: 10)),
                            ]),
                      ),
                      if ((r['device_id'] ?? '').toString().isNotEmpty)
                        IconButton(
                            tooltip: 'نسخ معرّف الجهاز',
                            onPressed: () =>
                                copyDeviceId(context, '${r['device_id']}'),
                            icon: Icon(Icons.copy_rounded,
                                size: 18, color: XTheme.cyan)),
                      IconButton(
                          onPressed: () => _act(r['id'], 'approve'),
                          icon: Icon(Icons.check_circle,
                              color: XTheme.ok)),
                      IconButton(
                          onPressed: () => _act(r['id'], 'reject'),
                          icon:
                              Icon(Icons.cancel, color: XTheme.danger)),
                    ]),
                  ),
                )),
          ],
        ],
      ),
    );
  }

  Future<void> _act(String id, String action) async {
    try {
      await widget.api.requestAction(id, action);
      _load();
    } catch (_) {}
  }

  Widget _stat(String label, String value, IconData icon, Color color) {
    return GlassCard(
      padding: const EdgeInsets.all(14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(icon, color: color, size: 22),
          const Spacer(),
          Text(value,
              style: const TextStyle(
                  fontSize: 24, fontWeight: FontWeight.w900)),
          Text(label,
              style:
                  TextStyle(color: XTheme.textDim, fontSize: 12)),
        ],
      ),
    );
  }
}

// ============ الإعدادات ============

class _SettingsTab extends StatefulWidget {
  const _SettingsTab({required this.api, required this.store});
  final Api api;
  final Store store;
  @override
  State<_SettingsTab> createState() => _SettingsTabState();
}

class _SettingsTabState extends State<_SettingsTab> {
  XSettings? _s;
  bool _saving = false;
  String? _msg;
  final _telegram = TextEditingController();
  final _minVer = TextEditingController();
  final _blockVer = TextEditingController();
  final _updMsg = TextEditingController();
  final _updUrl = TextEditingController();
  final _updImg = TextEditingController();
  final _hiddenMsg = TextEditingController();

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final r = await widget.api.ownerSettings();
      if (mounted) {
        setState(() {
          _s = XSettings.fromJson(r['settings']);
          _telegram.text = _s!.telegramLink;
          _minVer.text = '${_s!.minVersion}';
          _updMsg.text = _s!.updateMessage;
          _updUrl.text = _s!.updateUrl;
          _updImg.text = _s!.updateImageUrl;
          _hiddenMsg.text = _s!.videosHiddenMessage;
        });
      }
    } catch (_) {}
  }

  Future<void> _save() async {
    setState(() {
      _saving = true;
      _msg = null;
    });
    try {
      _s!.telegramLink = _telegram.text.trim();
      // القواعد في version_rules.dart كي تُفحص بلا واجهة — العطل الأصلي كان
      // في هذه القفزة بالذات: `int.tryParse('1.4.0')` تُعيد null فيُحفظ 1.
      final badMin = minVersionError(_minVer.text);
      if (badMin != null) {
        setState(() {
          _saving = false;
          _msg = badMin;
        });
        return;
      }
      final minVer = int.parse(_minVer.text.trim());
      final badBlock = blockWithoutExitError(
        minVersion: minVer,
        hasBlockedVersions: _s!.blockedVersions.isNotEmpty,
        updateMessage: _updMsg.text,
        updateUrl: _updUrl.text,
      );
      if (badBlock != null) {
        setState(() {
          _saving = false;
          _msg = badBlock;
        });
        return;
      }
      _s!.minVersion = minVer;
      _s!.updateMessage = _updMsg.text.trim();
      _s!.updateUrl = _updUrl.text.trim();
      _s!.updateImageUrl = _updImg.text.trim();
      _s!.videosHiddenMessage = _hiddenMsg.text.trim();
      final r = await widget.api.saveSettings(_s!.toJson());
      final saved = XSettings.fromJson(r['settings']);
      // تُطبَّق فوراً على التطبيق كله بلا انتظار دورة تحديث.
      await AppConfig.instance.applyOwnerSettings(
        telegram: saved.telegramLink,
        packages: saved.packages
            .map((p) => {
                  'cards': p.cards,
                  'price': p.price,
                  'days': p.days,
                  'desc': p.desc,
                })
            .toList(),
        dailyFree: saved.dailyFreeQuota,
        dailyGift: saved.dailyFreeQuota,
        videosHidden: saved.videosHidden,
        videosHiddenMessage: saved.videosHiddenMessage,
      );
      setState(() {
        _s = saved;
        _msg = 'تم الحفظ';
      });
    } catch (_) {
      setState(() => _msg = 'فشل الحفظ');
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_s == null) {
      return Center(
          child: CircularProgressIndicator(color: XTheme.accent));
    }
    final s = _s!;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        GlassCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(children: [
                Icon(Icons.bolt, color: XTheme.gold, size: 20),
                SizedBox(width: 8),
                Text('المنحة اليومية للجميع',
                    style: TextStyle(fontWeight: FontWeight.w900)),
              ]),
              const SizedBox(height: 6),
              Text(
                  'عدد العملات التي يستلمها المستخدم عبر العجلة كل 24 ساعة كاملة. '
                  'رصيد واحد للمخططات والتوافقات، دون منحة تلقائية إضافية.',
                  style: TextStyle(color: XTheme.textDim, fontSize: 12)),
              const SizedBox(height: 8),
              Row(children: [
                Expanded(
                  child: Slider(
                    value: s.dailyFreeQuota.toDouble().clamp(0, 50),
                    max: 50,
                    divisions: 50,
                    onChanged: (v) =>
                        setState(() => s.dailyFreeQuota = v.round()),
                  ),
                ),
                Container(
                  width: 52,
                  padding: const EdgeInsets.symmetric(vertical: 6),
                  decoration: BoxDecoration(
                      color: XTheme.gold.withOpacity(.12),
                      borderRadius: BorderRadius.circular(10)),
                  child: Text('${s.dailyFreeQuota}',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                          fontWeight: FontWeight.w900,
                          color: XTheme.gold,
                          fontSize: 17)),
                ),
              ]),
              if (s.dailyFreeQuota == 0)
                Text('صفر يعني بلا منحة مجانية — العملات وحدها تعمل',
                    style: TextStyle(color: XTheme.danger, fontSize: 11.5)),
            ],
          ),
        ),
        const SizedBox(height: 12),
        GlassCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('الفيديوهات',
                  style: TextStyle(fontWeight: FontWeight.w900, fontSize: 14)),
              const SizedBox(height: 4),
              Text(
                  'إيقاف فوري لعرض كل الفيديوهات على كل الأجهزة. الإيقاف يعمل '
                  'على الخادم، فلا يتجاوزه جهاز فتح الفيديو قبل تفعيله ولا نسخة '
                  'قديمة من التطبيق.',
                  style: TextStyle(color: XTheme.textDim, fontSize: 12)),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                value: s.videosHidden,
                onChanged: (v) => setState(() => s.videosHidden = v),
                title: Text(s.videosHidden ? 'العرض موقوف' : 'العرض يعمل',
                    style: const TextStyle(
                        fontWeight: FontWeight.w800, fontSize: 13.5)),
              ),
              if (s.videosHidden) ...[
                const SizedBox(height: 6),
                TextField(
                  controller: _hiddenMsg,
                  maxLength: 300,
                  decoration: const InputDecoration(
                    labelText: 'الرسالة التي يراها المستخدم',
                    border: OutlineInputBorder(),
                  ),
                ),
                FilledButton.icon(
                  onPressed: _saving ? null : _save,
                  icon: const Icon(Icons.save, size: 17),
                  label: const Text('حفظ الرسالة وتطبيق الإيقاف'),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 12),
        GlassCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(children: [
                Icon(Icons.system_update_alt,
                    color: XTheme.cyan, size: 20),
                SizedBox(width: 8),
                Text('التحكم بالإصدارات',
                    style: TextStyle(fontWeight: FontWeight.w900)),
              ]),
              const SizedBox(height: 6),
              // شرح صريح لأن الخطأ الشائع هو كتابة اسم الإصدار (2.0.0)
              // بدل رقم البناء، وكلاهما يبدو «إصداراً» في نظر المالك.
              Text(
                  'اكتب رقم البناء الظاهر في «التثبيتات حسب الإصدار» أعلاه '
                  '(مثال: 5)، لا اسم الإصدار مثل 2.0.0.',
                  style: TextStyle(color: XTheme.textDim, fontSize: 12)),
              const SizedBox(height: 12),
              TextField(
                controller: _minVer,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(
                    labelText: 'أدنى رقم بناء مسموح',
                    helperText: 'كل بناء أقدم من هذا الرقم يُقفل',
                    isDense: true),
              ),
              const SizedBox(height: 10),
              Row(children: [
                Expanded(
                  child: TextField(
                    controller: _blockVer,
                    keyboardType: TextInputType.number,
                    decoration: const InputDecoration(
                        labelText: 'إيقاف رقم بناء محدد',
                        helperText: 'للتراجع عن إصدار بعينه',
                        isDense: true),
                  ),
                ),
                const SizedBox(width: 8),
                IconButton.filled(
                  onPressed: () {
                    final raw = _blockVer.text.trim();
                    final v = int.tryParse(raw);
                    // الرقم غير الصالح كان يُتجاهل بلا أي أثر: يضغط المالك
                    // الزر ولا يحدث شيء ولا يعرف السبب.
                    if (v == null) {
                      setState(() => _msg =
                          'رقم البناء غير صالح — اكتب رقماً فقط (مثال: 5)');
                      return;
                    }
                    if (s.blockedVersions.contains(v)) {
                      setState(() => _msg = 'هذا البناء موقوف أصلاً');
                      return;
                    }
                    setState(() {
                      s.blockedVersions.add(v);
                      _blockVer.clear();
                      _msg = 'أُضيف البناء $v — اضغط حفظ لتطبيقه';
                    });
                  },
                  icon: const Icon(Icons.block, size: 18),
                  style: IconButton.styleFrom(
                      backgroundColor: XTheme.danger.withOpacity(.15),
                      foregroundColor: XTheme.danger),
                ),
              ]),
              if (s.blockedVersions.isNotEmpty) ...[
                const SizedBox(height: 10),
                Wrap(
                  spacing: 8,
                  children: s.blockedVersions
                      .map((v) => Chip(
                            label: Text('v$v'),
                            deleteIcon:
                                const Icon(Icons.close, size: 16),
                            onDeleted: () => setState(
                                () => s.blockedVersions.remove(v)),
                            backgroundColor:
                                XTheme.danger.withOpacity(.12),
                          ))
                      .toList(),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 12),
        GlassCard(
          child: Column(children: [
            _switch('قفل المخططات عن الزوار',
                'الزائر يحتاج حساباً مفعّلاً لعرض المخططات',
                s.schematicsLocked,
                (v) => setState(() => s.schematicsLocked = v)),
            const Divider(height: 20),
            _switch('قفل التوافقات عن الزوار',
                'الزائر يحتاج حساباً مفعّلاً لعرض التوافقات',
                s.compatLocked,
                (v) => setState(() => s.compatLocked = v)),
            const Divider(height: 20),
            // ثمن دخول الشركة — نفس عملة المنحة والعملات، يضبطه المالك.
            Row(children: [
              Expanded(
                child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('ثمن دخول الشركة',
                          style: TextStyle(fontWeight: FontWeight.w800)),
                      const SizedBox(height: 4),
                      Text(
                          s.compatSearchCost == 0
                              ? 'مجاني — بلا خصم'
                              : 'يُخصم ${s.compatSearchCost} من العملات عند دخول شركة '
                                  'بعد نفاد المنحة اليومية',
                          style: TextStyle(
                              color: XTheme.textDim, fontSize: 12)),
                    ]),
              ),
              IconButton(
                onPressed: s.compatSearchCost <= 0
                    ? null
                    : () => setState(() => s.compatSearchCost--),
                icon: const Icon(Icons.remove_circle_outline, size: 20),
              ),
              Container(
                width: 46,
                padding: const EdgeInsets.symmetric(vertical: 6),
                decoration: BoxDecoration(
                    color: XTheme.gold.withOpacity(.12),
                    borderRadius: BorderRadius.circular(10)),
                child: Text('${s.compatSearchCost}',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                        fontWeight: FontWeight.w900,
                        color: XTheme.gold,
                        fontSize: 16)),
              ),
              IconButton(
                onPressed: s.compatSearchCost >= 100
                    ? null
                    : () => setState(() => s.compatSearchCost++),
                icon: const Icon(Icons.add_circle_outline, size: 20),
              ),
            ]),
            const Divider(height: 20),
            // ثمن فتح ملف مخطط — نفس عملة المنحة والعملات.
            // صفر يعني مجاني تماماً بلا خصم أي عملة، وليس «سعراً افتراضياً».
            Row(children: [
              Expanded(
                child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('ثمن فتح المخطط',
                          style: TextStyle(fontWeight: FontWeight.w800)),
                      const SizedBox(height: 4),
                      Text(
                          s.schemFilePrice == 0
                              ? 'مجاني — بلا خصم أي عملة'
                              : 'يُخصم ${s.schemFilePrice} من العملات عند فتح ملف '
                                  'مخطط بعد نفاد المنحة اليومية',
                          style: TextStyle(
                              color: XTheme.textDim, fontSize: 12)),
                    ]),
              ),
              IconButton(
                onPressed: s.schemFilePrice <= 0
                    ? null
                    : () => setState(() => s.schemFilePrice--),
                icon: const Icon(Icons.remove_circle_outline, size: 20),
              ),
              Container(
                width: 46,
                padding: const EdgeInsets.symmetric(vertical: 6),
                decoration: BoxDecoration(
                    color: XTheme.gold.withOpacity(.12),
                    borderRadius: BorderRadius.circular(10)),
                child: Text('${s.schemFilePrice}',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                        fontWeight: FontWeight.w900,
                        color: XTheme.gold,
                        fontSize: 16)),
              ),
              IconButton(
                onPressed: s.schemFilePrice >= 100
                    ? null
                    : () => setState(() => s.schemFilePrice++),
                icon: const Icon(Icons.add_circle_outline, size: 20),
              ),
            ]),
            const Divider(height: 20),
            _switch('قفل التطبيق كلياً',
                'إيقاف التطبيق لجميع المستخدمين (صيانة)', s.appLocked,
                (v) => setState(() => s.appLocked = v)),
          ]),
        ),
        const SizedBox(height: 12),
        GlassCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(children: [
                Icon(Icons.new_releases_outlined,
                    color: XTheme.gold, size: 20),
                SizedBox(width: 8),
                Text('شاشة التحديث الإجباري',
                    style: TextStyle(fontWeight: FontWeight.w900)),
              ]),
              const SizedBox(height: 6),
              Text(
                  'تظهر للمستخدمين عند إيقاف إصدارهم أو رفع الحد الأدنى',
                  style: TextStyle(color: XTheme.textDim, fontSize: 12)),
              const SizedBox(height: 12),
              TextField(
                controller: _updMsg,
                maxLines: 2,
                decoration: const InputDecoration(
                    labelText: 'رسالة التحديث', isDense: true),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: _updUrl,
                decoration: const InputDecoration(
                    labelText: 'رابط زر التحديث (APK/متجر)',
                    isDense: true),
                textDirection: TextDirection.ltr,
              ),
              const SizedBox(height: 10),
              TextField(
                controller: _updImg,
                decoration: const InputDecoration(
                    labelText: 'رابط صورة التحديث (اختياري)',
                    isDense: true),
                textDirection: TextDirection.ltr,
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        // محرر باقات البطاقات — السعر والصلاحية والوصف والعدد
        GlassCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(children: [
                const CoinIcon(size: 20),
                const SizedBox(width: 8),
                const Expanded(
                  child: Text('باقات بطاقات المخططات',
                      style:
                          TextStyle(fontWeight: FontWeight.w900)),
                ),
                IconButton(
                  tooltip: 'إضافة باقة',
                  icon: Icon(Icons.add_circle,
                      color: XTheme.cyan, size: 22),
                  onPressed: () => _packageDialog(-1),
                ),
              ]),
              Text('تظهر للمستخدم عند ضغط زر + لشراء البطاقات',
                  style: TextStyle(
                      color: XTheme.textDim, fontSize: 11)),
              const SizedBox(height: 6),
              ...s.packages.asMap().entries.map((e) {
                final i = e.key;
                final p = e.value;
                return ListTile(
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  leading: const CoinIcon(size: 18),
                  title: Text('${p.cards} بطاقة — ${p.price}',
                      style: const TextStyle(
                          fontWeight: FontWeight.w800, fontSize: 13.5)),
                  subtitle: Text(
                      '${p.days > 0 ? '${p.days} يوم' : 'بلا انتهاء'}${p.desc.isNotEmpty ? ' • ${p.desc}' : ''}',
                      style: TextStyle(
                          color: XTheme.textDim, fontSize: 11)),
                  trailing: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      IconButton(
                          icon: Icon(Icons.edit_outlined,
                              size: 19, color: XTheme.accent),
                          onPressed: () => _packageDialog(i)),
                      IconButton(
                          icon: Icon(Icons.delete_outline,
                              size: 19, color: XTheme.danger),
                          onPressed: () =>
                              setState(() => s.packages.removeAt(i))),
                    ],
                  ),
                );
              }),
            ],
          ),
        ),
        const SizedBox(height: 12),
        GlassCard(
          child: TextField(
            controller: _telegram,
            decoration: const InputDecoration(
                labelText: 'رابط تيليجرام المالك',
                prefixIcon: Icon(Icons.send_rounded)),
            textDirection: TextDirection.ltr,
          ),
        ),
        const SizedBox(height: 18),
        if (_msg != null)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Text(_msg!,
                textAlign: TextAlign.center,
                // رسالة الفشل كانت تُعرض بالأخضر نفسه، فيقرأ المالك «فشل
                // الحفظ» أو «رقم غير صالح» كأنها نجاح ويمضي مطمئناً.
                style: TextStyle(
                    color: _msg == 'تم الحفظ' ? XTheme.ok : XTheme.danger)),
          ),
        _OwnerPanelSecurity(api: widget.api, store: widget.store),
        const SizedBox(height: 18),
        SizedBox(
          width: double.infinity,
          child: DecoratedBox(
            decoration: BoxDecoration(
                gradient: XTheme.gradient,
                borderRadius: BorderRadius.circular(XTheme.rMd),
                boxShadow: XTheme.glow(XTheme.accent, strength: .6)),
            child: ElevatedButton(
              onPressed: _saving ? null : _save,
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.transparent,
                shadowColor: Colors.transparent,
                padding: const EdgeInsets.symmetric(vertical: 15),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(XTheme.rMd)),
              ),
              child: Text(_saving ? 'جاري الحفظ…' : 'حفظ الإعدادات',
                  style: const TextStyle(
                      fontWeight: FontWeight.w800,
                      color: Colors.white)),
            ),
          ),
        ),
      ],
    );
  }

  /// حوار تحرير/إضافة باقة — index -1 = باقة جديدة
  void _packageDialog(int index) {
    final p = index >= 0 ? _s!.packages[index] : XPackage();
    final cards = TextEditingController(text: index >= 0 ? '${p.cards}' : '');
    final price = TextEditingController(text: p.price);
    final days = TextEditingController(text: index >= 0 ? '${p.days}' : '');
    final desc = TextEditingController(text: p.desc);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: XTheme.surface,
        shape:
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(22)),
        title: Text(index >= 0 ? 'تحرير باقة' : 'باقة جديدة',
            style: const TextStyle(
                fontWeight: FontWeight.w900, fontSize: 17)),
        content: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            TextField(
                controller: cards,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(
                    labelText: 'عدد البطاقات')),
            const SizedBox(height: 10),
            TextField(
                controller: price,
                decoration: const InputDecoration(
                    labelText: 'السعر (مثال: 3\$)')),
            const SizedBox(height: 10),
            TextField(
                controller: days,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(
                    labelText: 'الصلاحية بالأيام (0 = بلا انتهاء)')),
            const SizedBox(height: 10),
            TextField(
                controller: desc,
                decoration: const InputDecoration(
                    labelText: 'الوصف (مثال: صالحة شهرين)')),
          ]),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('إلغاء')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: XTheme.accent,
                foregroundColor: Colors.white),
            onPressed: () {
              final c = int.tryParse(cards.text) ?? 0;
              if (c <= 0) return;
              final np = XPackage(
                  cards: c,
                  price: price.text.trim(),
                  days: int.tryParse(days.text) ?? 0,
                  desc: desc.text.trim());
              setState(() {
                if (index >= 0) {
                  _s!.packages[index] = np;
                } else {
                  _s!.packages.add(np);
                }
              });
              Navigator.pop(ctx);
            },
            child: const Text('حفظ'),
          ),
        ],
      ),
    );
  }

  Widget _switch(
      String title, String sub, bool value, ValueChanged<bool> onChanged) {
    return SwitchListTile(
      contentPadding: EdgeInsets.zero,
      title: Text(title, style: const TextStyle(fontWeight: FontWeight.w700)),
      subtitle: Text(sub,
          style: TextStyle(color: XTheme.textDim, fontSize: 11)),
      value: value,
      onChanged: onChanged,
      activeColor: XTheme.cyan,
    );
  }
}

// ============ المستخدمون ============

class _UsersTab extends StatefulWidget {
  const _UsersTab({required this.api});
  final Api api;
  @override
  State<_UsersTab> createState() => _UsersTabState();
}

class _UsersTabState extends State<_UsersTab> {
  List<dynamic>? _users;
  final _search = TextEditingController();
  String _q = '';

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _search.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final u = await widget.api.ownerUsers(q: _q);
      if (mounted) setState(() => _users = u);
    } catch (_) {}
  }

  Future<void> _act(String id, String action, {int? days}) async {
    try {
      await widget.api.userAction(id, action, days: days);
      _load();
    } on ApiException catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text(e.message)));
      }
    }
  }

  void _addUserDialog() {
    final user = TextEditingController();
    final pass = TextEditingController();
    final name = TextEditingController();
    final days = TextEditingController(text: '30');
    final cards = TextEditingController(text: '150');
    final cardDays = TextEditingController(text: '60');
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: XTheme.surface,
        shape:
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(22)),
        title: const Text('إنشاء حساب مشترك',
            style: TextStyle(fontWeight: FontWeight.w900, fontSize: 17)),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          TextField(
              controller: user,
              decoration:
                  const InputDecoration(labelText: 'اسم المستخدم'),
              textDirection: TextDirection.ltr),
          const SizedBox(height: 10),
          TextField(
              controller: pass,
              decoration:
                  const InputDecoration(labelText: 'كلمة المرور'),
              textDirection: TextDirection.ltr),
          const SizedBox(height: 10),
          TextField(
              controller: name,
              decoration: const InputDecoration(
                  labelText: 'الاسم (اختياري)')),
          const SizedBox(height: 10),
          TextField(
              controller: days,
              keyboardType: TextInputType.number,
              decoration: const InputDecoration(
                  labelText: 'مدة الاشتراك بالأيام (0 = بلا انتهاء)')),
          const SizedBox(height: 10),
          TextField(
              controller: cards,
              keyboardType: TextInputType.number,
              decoration: const InputDecoration(
                  labelText: 'عدد بطاقات المخططات')),
          const SizedBox(height: 10),
          TextField(
              controller: cardDays,
              keyboardType: TextInputType.number,
              decoration: const InputDecoration(
                  labelText: 'صلاحية البطاقات بالأيام (0 = بلا انتهاء)')),
        ]),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('إلغاء')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: XTheme.accent,
                foregroundColor: Colors.white),
            onPressed: () async {
              try {
                await widget.api.createUser(
                    user.text.trim(), pass.text, name.text.trim(),
                    int.tryParse(days.text) ?? 0,
                    cards: int.tryParse(cards.text) ?? 0,
                    cardDays: int.tryParse(cardDays.text) ?? 0);
                if (ctx.mounted) Navigator.pop(ctx);
                _load();
              } on ApiException catch (e) {
                if (ctx.mounted) {
                  ScaffoldMessenger.of(context)
                      .showSnackBar(SnackBar(content: Text(e.message)));
                }
              }
            },
            child: const Text('إنشاء'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.transparent,
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _addUserDialog,
        backgroundColor: XTheme.accent,
        icon: const Icon(Icons.person_add_alt_1, color: Colors.white),
        label: const Text('حساب جديد',
            style: TextStyle(
                color: Colors.white, fontWeight: FontWeight.w800)),
      ),
      body: Column(children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(14, 14, 14, 4),
          child: TextField(
            controller: _search,
            onChanged: (v) => setState(() => _q = v.trim()),
            onSubmitted: (_) => _load(),
            decoration: InputDecoration(
              hintText: 'ابحث باسم المستخدم أو الاسم الظاهر أو معرّف الجهاز',
              isDense: true,
              prefixIcon: const Icon(Icons.search, size: 18),
              suffixIcon: _q.isEmpty
                  ? null
                  : IconButton(
                      icon: const Icon(Icons.close, size: 18),
                      onPressed: () {
                        _search.clear();
                        setState(() => _q = '');
                        _load();
                      },
                    ),
            ),
          ),
        ),
        Expanded(
          child: _users == null
              ? Center(
                  child: CircularProgressIndicator(color: XTheme.accent))
              : _users!.isEmpty
                  ? Center(
                      child: Text(
                          _q.isEmpty ? 'لا يوجد مستخدمون' : 'لا نتائج مطابقة',
                          style: TextStyle(color: XTheme.textDim)))
                  : RefreshIndicator(
                      onRefresh: _load,
                      color: XTheme.accent,
                      child: _list(),
                    ),
        ),
      ]),
    );
  }

  /// حوار شحن بطاقات مخططات لمستخدم — يُنفَّذ في السيرفر فقط
  void _quotaDialog(Map<String, dynamic> u) {
    final cards = TextEditingController(text: '150');
    final days = TextEditingController(text: '60');
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: XTheme.surface,
        shape:
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(22)),
        title: Text('شحن بطاقات — ${u['username']}',
            style: const TextStyle(
                fontWeight: FontWeight.w900, fontSize: 16)),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          Text('الرصيد الحالي: ${u['quota_balance'] ?? 0} بطاقة',
              style: TextStyle(color: XTheme.textDim, fontSize: 12)),
          const SizedBox(height: 10),
          TextField(
              controller: cards,
              keyboardType: TextInputType.number,
              decoration: const InputDecoration(
                  labelText: 'عدد البطاقات المضافة')),
          const SizedBox(height: 10),
          TextField(
              controller: days,
              keyboardType: TextInputType.number,
              decoration: const InputDecoration(
                  labelText: 'صلاحية البطاقات بالأيام (0 = بلا انتهاء)')),
        ]),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('إلغاء')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: XTheme.accent,
                foregroundColor: Colors.white),
            onPressed: () async {
              try {
                await widget.api.grantQuota(
                    u['id'],
                    int.tryParse(cards.text) ?? 0,
                    int.tryParse(days.text) ?? 0);
                if (ctx.mounted) Navigator.pop(ctx);
                _load();
              } on ApiException catch (e) {
                if (ctx.mounted) {
                  ScaffoldMessenger.of(context)
                      .showSnackBar(SnackBar(content: Text(e.message)));
                }
              }
            },
            child: const Text('شحن'),
          ),
        ],
      ),
    );
  }

  Widget _list() {
    return ListView.builder(
        padding: const EdgeInsets.all(14),
        itemCount: _users!.length,
        itemBuilder: (context, i) {
          final u = _users![i];
          final active = u['active'] == 1;
          final isOwner = u['role'] == 'owner';
          return Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: GlassCard(
              padding: const EdgeInsets.all(14),
              child: Row(children: [
                CircleAvatar(
                  backgroundColor:
                      (active ? XTheme.ok : XTheme.danger).withOpacity(.14),
                  child: Icon(
                      isOwner ? Icons.shield : Icons.person,
                      color: active ? XTheme.ok : XTheme.danger,
                      size: 20),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(u['username'] ?? '',
                            style: const TextStyle(
                                fontWeight: FontWeight.w800)),
                        Text(
                            '${u['role']} • ${active ? 'مفعّل' : 'موقوف'} • جهاز: ${u['device_id'] ?? '—'}',
                            style: TextStyle(
                                color: XTheme.textDim, fontSize: 11)),
                        if (!isOwner)
                          Text(
                            'بطاقات: ${u['quota_balance'] ?? 0}'
                            '${(u['quota_expires_at'] ?? 0) > 0 ? ' • حتى ${DateTime.fromMillisecondsSinceEpoch(u['quota_expires_at']).toLocal().toString().split(' ').first}' : ''}',
                            style: TextStyle(
                                color: XTheme.cyan, fontSize: 11)),
                      ]),
                ),
                if ((u['device_id'] ?? '').toString().isNotEmpty)
                  IconButton(
                      tooltip: 'نسخ معرّف الجهاز',
                      onPressed: () =>
                          copyDeviceId(context, '${u['device_id']}'),
                      icon: Icon(Icons.copy_rounded,
                          size: 18, color: XTheme.cyan)),
                if (!isOwner)
                  PopupMenuButton<String>(
                    icon: Icon(Icons.more_vert,
                        color: XTheme.textDim),
                    color: XTheme.surface2,
                    onSelected: (a) {
                      if (a == 'extend') {
                        _act(u['id'], 'extend', days: 30);
                      } else if (a == 'quota') {
                        _quotaDialog(u);
                      } else {
                        _act(u['id'], a);
                      }
                    },
                    itemBuilder: (_) => [
                      PopupMenuItem(
                          value: active ? 'deactivate' : 'activate',
                          child: Text(active ? 'إيقاف' : 'تفعيل')),
                      const PopupMenuItem(
                          value: 'quota',
                          child: Text('شحن بطاقات مخططات')),
                      const PopupMenuItem(
                          value: 'extend',
                          child: Text('تمديد 30 يوم')),
                      const PopupMenuItem(
                          value: 'reset-device',
                          child: Text('فك ربط الجهاز')),
                      const PopupMenuItem(
                          value: 'delete', child: Text('حذف')),
                    ],
                  ),
              ]),
            ),
          );
        },
      );
  }
}

// ============ سجل الأمان ============

class _SecurityTab extends StatefulWidget {
  const _SecurityTab({required this.api});
  final Api api;
  @override
  State<_SecurityTab> createState() => _SecurityTabState();
}

class _SecurityTabState extends State<_SecurityTab> {
  List<dynamic>? _events;

  /// افتراضياً تُعرض الهجمات فقط؛ التبديل يكشف الأحداث الروتينية عند الحاجة.
  bool _attacksOnly = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final e = await widget.api.ownerSecurity(all: !_attacksOnly);
      if (mounted) setState(() => _events = e);
    } catch (_) {}
  }

  static const _labels = {
    'bad_signature': ('توقيع مزوّر', XTheme.danger),
    'missing_signature': ('طلب بلا توقيع', XTheme.danger),
    'stale_signature': ('توقيع منتهي', XTheme.gold),
    'rate_limited': ('هجوم طلبات مكثفة', XTheme.danger),
    'device_mismatch': ('حساب من جهاز غريب', XTheme.gold),
    'device_farm': ('مزرعة أجهزة', XTheme.danger),
    'bad_login': ('دخول فاشل', XTheme.gold),
    'bad_owner_key': ('مفتاح مالك خاطئ', XTheme.danger),
    'ip_hardban': ('حظر IP تلقائي', XTheme.danger),
    'non_owner_admin_attempt': ('محاولة وصول للوحة', XTheme.danger),
    'guest_token_device_mismatch': ('توكن زائر مسروق', XTheme.danger),
    'banned_ip_hit': ('وصول من IP محظور', XTheme.danger),
    'banned_device_hit': ('وصول من جهاز محظور', XTheme.danger),
    'device_banned': ('حظر جهاز', XTheme.danger),
    'ip_banned': ('حظر IP', XTheme.danger),
    'security_logs_cleared': ('حذف سجلات الأمان', XTheme.gold),
  };

  Future<void> _copy(String value, String what) async {
    await Clipboard.setData(ClipboardData(text: value));
    if (mounted) {
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('تم نسخ $what')));
    }
  }

  Future<void> _ban(String? deviceId, String? addr, String reason) async {
    try {
      if (deviceId != null && deviceId.isNotEmpty) {
        await widget.api.banDevice(deviceId, 'ban_from_security:$reason');
      }
      if (addr != null && addr.isNotEmpty) {
        await widget.api.banIp(addr, 'ban_from_security:$reason');
      }
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(const SnackBar(content: Text('تم الحظر')));
      }
    } on ApiException catch (ex) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text(ex.message)));
      }
    }
  }

  /// يمسح السجل: الكل، أو نوعاً واحداً، أو ما قبل تاريخ.
  Future<void> _clearLogs({String? reason}) async {
    final label = reason == null
        ? 'كل السجلات'
        : (_labels[reason]?.$1 ?? reason);
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: const Text('حذف السجلات؟'),
        content: Text('سيُحذف $label نهائياً ولا يمكن التراجع.',
            style: const TextStyle(fontSize: 12.5)),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(c, false),
              child: const Text('إلغاء')),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: XTheme.danger),
            onPressed: () => Navigator.pop(c, true),
            child: const Text('حذف'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    try {
      final n = await widget.api.clearSecurityLogs(reason: reason);
      await _load();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('حُذف $n سجلاً')));
      }
    } on ApiException catch (ex) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text(ex.message)));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(14, 12, 14, 4),
          child: Row(children: [
            Expanded(
              child: Text('الهجمات ومحاولات التجاوز فقط',
                  style: TextStyle(
                      fontSize: 12.5,
                      fontWeight: FontWeight.w700,
                      color: XTheme.textDim)),
            ),
            Switch(
              value: _attacksOnly,
              activeColor: XTheme.accent,
              onChanged: (v) {
                setState(() => _attacksOnly = v);
                _load();
              },
            ),
            Text('هجمات فقط',
                style: TextStyle(fontSize: 12, color: XTheme.textDim)),
          ]),
        ),
        // حذف السجلات — مسح الكل أو نوع واحد فقط.
        Padding(
          padding: const EdgeInsets.fromLTRB(14, 0, 14, 8),
          child: Row(children: [
            Expanded(
              child: OutlinedButton.icon(
                onPressed: _events == null || _events!.isEmpty
                    ? null
                    : () => _clearLogs(),
                icon: Icon(Icons.delete_sweep_outlined,
                    size: 18, color: XTheme.danger),
                label: const Text('حذف كل السجلات'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: XTheme.danger,
                  side: BorderSide(color: XTheme.danger.withOpacity(.5)),
                ),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: OutlinedButton.icon(
                onPressed: _events == null || _events!.isEmpty
                    ? null
                    : _pickReasonToClear,
                icon: const Icon(Icons.filter_alt_off_outlined, size: 18),
                label: const Text('حذف نوع محدد'),
              ),
            ),
          ]),
        ),
        Expanded(child: _list()),
      ],
    );
  }

  /// اختيار نوع حدث لحذفه وحده — بدل مسح السجل كله.
  Future<void> _pickReasonToClear() async {
    final types = <String>{
      ...?_events
          ?.map((e) => e['reason']?.toString())
          .whereType<String>(),
      ..._labels.keys,
    }.toList()
      ..sort((a, b) =>
          (_labels[a]?.$1 ?? a).compareTo(_labels[b]?.$1 ?? b));
    final picked = await showModalBottomSheet<String>(
      context: context,
      backgroundColor: XTheme.surface,
      builder: (c) => SafeArea(
        child: ListView(
          shrinkWrap: true,
          children: [
            Padding(
              padding: const EdgeInsets.all(14),
              child: Text('اختر نوع الحدث لحذفه',
                  style: TextStyle(
                      fontWeight: FontWeight.w800, color: XTheme.textDim)),
            ),
            for (final r in types)
              ListTile(
                dense: true,
                leading: Icon(
                  Icons.shield_outlined,
                  size: 18,
                  // اللون يميّز الخطورة كما في بطاقة الحدث.
                  color: _labels[r]?.$2 ?? XTheme.gold,
                ),
                title: Text(_labels[r]?.$1 ?? r),
                subtitle: Text(r,
                    style: const TextStyle(fontSize: 10),
                    textDirection: TextDirection.ltr),
                onTap: () => Navigator.pop(c, r),
              ),
          ],
        ),
      ),
    );
    if (picked != null) await _clearLogs(reason: picked);
  }

  Widget _list() {
    if (_events == null) {
      return Center(child: CircularProgressIndicator(color: XTheme.accent));
    }
    if (_events!.isEmpty) {
      return Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Icon(Icons.verified_user, size: 48, color: XTheme.ok),
          const SizedBox(height: 10),
          Text(_attacksOnly ? 'لا توجد هجمات مسجّلة' : 'لا توجد أحداث',
              style: TextStyle(color: XTheme.textDim)),
        ]),
      );
    }
    return RefreshIndicator(
      onRefresh: _load,
      color: XTheme.accent,
      child: ListView.builder(
        padding: const EdgeInsets.all(14),
        itemCount: _events!.length,
        itemBuilder: (context, i) => _eventCard(_events![i]),
      ),
    );
  }

  Widget _eventCard(dynamic e) {
    final reason = e['reason']?.toString() ?? '?';
    final meta = _labels[reason] ?? (reason, XTheme.gold);
    final deviceId = (e['device_id'] ?? '').toString();
    final addr = (e['ip'] ?? '').toString();
    final at = e['at']?.toString() ?? '';
    final detail = (e['detail'] ?? '').toString();

    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: GlassCard(
        padding: const EdgeInsets.all(14),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Icon(Icons.gpp_maybe_rounded, color: meta.$2, size: 20),
            const SizedBox(width: 9),
            Expanded(
              child: Text(meta.$1,
                  style: TextStyle(
                      fontWeight: FontWeight.w800,
                      color: meta.$2,
                      fontSize: 13.5)),
            ),
            Text(at.length >= 19 ? at.substring(0, 19).replaceAll('T', ' ') : at,
                style: TextStyle(color: XTheme.textDim, fontSize: 10.5)),
          ]),
          const SizedBox(height: 10),
          if (addr.isNotEmpty && addr != 'unknown')
            _field('IP', addr, XTheme.cyan, () => _ban(null, addr, reason)),
          if (deviceId.isNotEmpty)
            _field('معرّف الجهاز', deviceId, XTheme.accent,
                () => _ban(deviceId, null, reason)),
          if (detail.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(top: 6),
              child: Text(detail,
                  style: TextStyle(
                      color: XTheme.textDim, fontSize: 11, height: 1.5)),
            ),
          const SizedBox(height: 10),
          Row(children: [
            if (deviceId.isNotEmpty || (addr.isNotEmpty && addr != 'unknown'))
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => _ban(
                      deviceId.isEmpty ? null : deviceId,
                      (addr.isEmpty || addr == 'unknown') ? null : addr,
                      reason),
                  icon: const Icon(Icons.block, size: 18),
                  label: const Text('حظر الجهاز و IP'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: XTheme.danger,
                    side: BorderSide(color: XTheme.danger.withOpacity(.5)),
                  ),
                ),
              ),
          ]),
        ]),
      ),
    );
  }

  /// سطر حقل حسّاس مع زر نسخ — المالك يحتاج نقل الـID/IP لمنعهما.
  Widget _field(String label, String value, Color color, VoidCallback onBan) =>
      Padding(
        padding: const EdgeInsets.only(bottom: 6),
        child: Row(children: [
          SizedBox(
            width: 82,
            child: Text(label,
                style: TextStyle(color: XTheme.textDim, fontSize: 11.5)),
          ),
          Expanded(
            child: SelectableText(value,
                maxLines: 1,
                style: TextStyle(
                    fontSize: 11.5,
                    color: color,
                    fontWeight: FontWeight.w700)),
          ),
          IconButton(
            tooltip: 'نسخ $label',
            visualDensity: VisualDensity.compact,
            icon: Icon(Icons.copy_rounded, size: 16, color: XTheme.textDim),
            onPressed: () => _copy(value, label),
          ),
          IconButton(
            tooltip: 'حظر $label',
            visualDensity: VisualDensity.compact,
            icon: Icon(Icons.gpp_bad_rounded, size: 18, color: XTheme.danger),
            onPressed: onBan,
          ),
        ]),
      );
}

// ============ الإعلانات ============

class _AnnouncementsTab extends StatefulWidget {
  const _AnnouncementsTab({required this.api});
  final Api api;
  @override
  State<_AnnouncementsTab> createState() => _AnnouncementsTabState();
}

class _AnnouncementsTabState extends State<_AnnouncementsTab> {
  List<dynamic>? _ads;
  bool _posting = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final a = await widget.api.ownerAnnouncements();
      if (mounted) setState(() => _ads = a);
    } catch (_) {
      if (mounted) setState(() => _ads = []);
    }
  }

  void _compose() {
    final title = TextEditingController();
    final subtitle = TextEditingController();
    final link = TextEditingController();
    String? b64;
    String? ext;
    String? previewName;

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setSheet) => Container(
          margin: const EdgeInsets.all(14),
          padding: EdgeInsets.only(
              left: 22, right: 22, top: 22,
              bottom: MediaQuery.of(ctx).viewInsets.bottom + 22),
          decoration: BoxDecoration(
              color: XTheme.surface,
              borderRadius: BorderRadius.circular(26)),
          child: SingleChildScrollView(
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              const Text('نشر إعلان جديد',
                  style: TextStyle(fontWeight: FontWeight.w900, fontSize: 17)),
              const SizedBox(height: 14),
              TextField(
                  controller: title,
                  decoration: const InputDecoration(labelText: 'العنوان *')),
              const SizedBox(height: 10),
              TextField(
                  controller: subtitle,
                  decoration:
                      const InputDecoration(labelText: 'النص الفرعي')),
              const SizedBox(height: 10),
              TextField(
                  controller: link,
                  decoration: const InputDecoration(
                      labelText: 'رابط عند الضغط (اختياري)'),
                  textDirection: TextDirection.ltr),
              const SizedBox(height: 10),
              OutlinedButton.icon(
                onPressed: () async {
                  final picked = await ImagePicker().pickImage(
                      source: ImageSource.gallery, maxWidth: 1600);
                  if (picked != null) {
                    final bytes = await picked.readAsBytes();
                    if (bytes.length > 4 * 1024 * 1024) return;
                    setSheet(() {
                      b64 = base64Encode(bytes);
                      ext = picked.name.split('.').last.toLowerCase();
                      previewName = picked.name;
                    });
                  }
                },
                icon: const Icon(Icons.image_outlined),
                label: Text(previewName ?? 'اختيار صورة الإعلان'),
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: double.infinity,
                child: DecoratedBox(
                  decoration: BoxDecoration(
                      gradient: XTheme.gradient,
                      borderRadius: BorderRadius.circular(16)),
                  child: ElevatedButton(
                    onPressed: _posting
                        ? null
                        : () async {
                            if (title.text.trim().isEmpty) return;
                            setSheet(() => _posting = true);
                            try {
                              await widget.api.createAnnouncement(
                                  title.text.trim(),
                                  subtitle.text.trim(),
                                  link.text.trim(),
                                  imageB64: b64,
                                  imageExt: ext);
                              if (ctx.mounted) Navigator.pop(ctx);
                              _load();
                            } catch (_) {}
                            setSheet(() => _posting = false);
                          },
                    style: ElevatedButton.styleFrom(
                        backgroundColor: Colors.transparent,
                        shadowColor: Colors.transparent,
                        padding: const EdgeInsets.symmetric(vertical: 14)),
                    child: Text(
                        _posting ? 'جاري النشر…' : 'نشر الإعلان',
                        style: const TextStyle(
                            fontWeight: FontWeight.w800,
                            color: Colors.white)),
                  ),
                ),
              ),
            ]),
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.transparent,
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _compose,
        backgroundColor: XTheme.accent2,
        icon: const Icon(Icons.add_photo_alternate_outlined,
            color: Colors.white),
        label: const Text('إعلان جديد',
            style: TextStyle(
                color: Colors.white, fontWeight: FontWeight.w800)),
      ),
      body: _ads == null
          ? Center(
              child: CircularProgressIndicator(color: XTheme.accent))
          : _ads!.isEmpty
              ? Center(
                  child: Text('لا إعلانات — انشر أول إعلان',
                      style: TextStyle(color: XTheme.textDim)))
              : RefreshIndicator(
                  onRefresh: _load,
                  color: XTheme.accent,
                  child: ListView.builder(
                    padding: const EdgeInsets.all(14),
                    itemCount: _ads!.length,
                    itemBuilder: (context, i) {
                      final a = _ads![i];
                      return Padding(
                        padding: const EdgeInsets.only(bottom: 8),
                        child: GlassCard(
                          padding: const EdgeInsets.all(14),
                          child: Row(children: [
                            Icon(Icons.campaign,
                                color: XTheme.gold, size: 22),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Column(
                                  crossAxisAlignment:
                                      CrossAxisAlignment.start,
                                  children: [
                                    Text(a['title'] ?? '',
                                        style: const TextStyle(
                                            fontWeight:
                                                FontWeight.w800)),
                                    if ((a['subtitle'] ?? '')
                                        .toString()
                                        .isNotEmpty)
                                      Text(a['subtitle'],
                                          style: TextStyle(
                                              color: XTheme.textDim,
                                              fontSize: 12)),
                                    if ((a['imageUrl'] ?? '')
                                        .toString()
                                        .isNotEmpty)
                                      Text('مع صورة',
                                          style: TextStyle(
                                              color: XTheme.cyan,
                                              fontSize: 11)),
                                  ]),
                            ),
                            IconButton(
                              onPressed: () async {
                                await widget.api
                                    .deleteAnnouncement(a['id']);
                                _load();
                              },
                              icon: Icon(Icons.delete_outline,
                                  color: XTheme.danger),
                            ),
                          ]),
                        ),
                      );
                    },
                  ),
                ),
    );
  }
}

// ============ حظر الأجهزة ============

class _BansTab extends StatefulWidget {
  const _BansTab({required this.api});
  final Api api;
  @override
  State<_BansTab> createState() => _BansTabState();
}

class _BansTabState extends State<_BansTab> {
  List<dynamic>? _bans;
  final _dev = TextEditingController();

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final b = await widget.api.ownerBans();
      if (mounted) setState(() => _bans = b);
    } catch (_) {
      if (mounted) setState(() => _bans = []);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      Padding(
        padding: const EdgeInsets.all(14),
        child: GlassCard(
          padding: const EdgeInsets.all(12),
          child: Row(children: [
            Expanded(
              child: TextField(
                controller: _dev,
                decoration: const InputDecoration(
                    hintText: 'معرّف الجهاز للحظر النهائي',
                    isDense: true),
                textDirection: TextDirection.ltr,
              ),
            ),
            const SizedBox(width: 8),
            IconButton.filled(
              onPressed: () async {
                if (_dev.text.trim().isEmpty) return;
                await widget.api
                    .banDevice(_dev.text.trim(), 'manual-owner');
                _dev.clear();
                _load();
              },
              icon: const Icon(Icons.block, size: 18),
              style: IconButton.styleFrom(
                  backgroundColor: XTheme.danger.withOpacity(.2),
                  foregroundColor: XTheme.danger),
            ),
          ]),
        ),
      ),
      Expanded(
        child: _bans == null
            ? Center(
                child: CircularProgressIndicator(color: XTheme.accent))
            : _bans!.isEmpty
                ? Center(
                    child: Text('لا أجهزة محظورة',
                        style: TextStyle(color: XTheme.textDim)))
                : RefreshIndicator(
                    onRefresh: _load,
                    color: XTheme.accent,
                    child: ListView.builder(
                      padding: const EdgeInsets.fromLTRB(14, 0, 14, 24),
                      itemCount: _bans!.length,
                      itemBuilder: (context, i) {
                        final b = _bans![i];
                        return Padding(
                          padding: const EdgeInsets.only(bottom: 8),
                          child: GlassCard(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 14, vertical: 10),
                            child: Row(children: [
                              Icon(Icons.phonelink_erase,
                                  color: XTheme.danger, size: 20),
                              const SizedBox(width: 10),
                              Expanded(
                                child: Column(
                                    crossAxisAlignment:
                                        CrossAxisAlignment.start,
                                    children: [
                                      Text(b['id'] ?? '',
                                          style: const TextStyle(
                                              fontWeight:
                                                  FontWeight.w700,
                                              fontSize: 13)),
                                      Text(
                                          '${b['reason'] ?? ''} • ${b['at']?.toString().substring(0, 10) ?? ''}',
                                          style: TextStyle(
                                              color: XTheme.textDim,
                                              fontSize: 11)),
                                    ]),
                              ),
                              TextButton(
                                onPressed: () async {
                                  await widget.api
                                      .unbanDevice(b['id']);
                                  _load();
                                },
                                child: Text('فك الحظر',
                                    style: TextStyle(
                                        color: XTheme.ok,
                                        fontSize: 12)),
                              ),
                            ]),
                          ),
                        );
                      },
                    ),
                  ),
      ),
    ]);
  }
}

// ============ محافظ الزوار ============

/// بطاقة رقم صغيرة داخل رأس محافظ الزوار (إجمالي/صفر/بلا صلاحية).
class _WalletStat extends StatelessWidget {
  const _WalletStat(
      {required this.label, required this.value, required this.color});
  final String label;
  final String value;
  final Color color;
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 6),
      decoration: BoxDecoration(
        color: color.withOpacity(.10),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(children: [
        Text(value,
            style: TextStyle(
                fontWeight: FontWeight.w900, fontSize: 16, color: color)),
        const SizedBox(height: 2),
        Text(label,
            textAlign: TextAlign.center,
            style: TextStyle(color: XTheme.textDim, fontSize: 10)),
      ]),
    );
  }
}

/// وسم صغير لأيقونة + نص (اسم/إصدار/IP/تاريخ).
class _Chip extends StatelessWidget {
  const _Chip({required this.icon, required this.text});
  final IconData icon;
  final String text;
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: XTheme.textDim.withOpacity(.10),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(icon, size: 11, color: XTheme.textDim),
        const SizedBox(width: 4),
        Text(text,
            style: TextStyle(color: XTheme.textDim, fontSize: 10.5),
            textDirection: TextDirection.ltr),
      ]),
    );
  }
}

/// محافظ الزوار: عملات تُشحن لجهاز بلا حساب.
///
/// الزائر لم يكن له رصيد إطلاقاً، فكانت حصته المجانية إن نفدت يتوقف تماماً
/// حتى لو دفع. هذه الشاشة تمنحه رصيداً بمفتاح الجهاز — نفس المفتاح الذي
/// يعتمد عليه الخادم في الخصم.
class _WalletsTab extends StatefulWidget {
  const _WalletsTab({required this.api});
  final Api api;
  @override
  State<_WalletsTab> createState() => _WalletsTabState();
}

class _WalletsTabState extends State<_WalletsTab> {
  List<dynamic>? _rows;
  final _dev = TextEditingController();
  final _coins = TextEditingController(text: '5');
  final _days = TextEditingController(text: '30');
  final _search = TextEditingController();
  String _q = '';
  bool _bulkAll = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _dev.dispose();
    _coins.dispose();
    _days.dispose();
    _search.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final w = await widget.api.ownerWallets(q: _q);
      if (mounted) setState(() => _rows = w);
    } catch (_) {
      if (mounted) setState(() => _rows = []);
    }
  }

  Future<void> _grant() async {
    final dev = _dev.text.trim();
    final coins = int.tryParse(_coins.text.trim()) ?? 0;
    if (dev.isEmpty || coins <= 0) return;
    final days = int.tryParse(_days.text.trim()) ?? 0;
    try {
      await widget.api.grantWallet(dev, coins, days);
      _dev.clear();
      await _load();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('فشل الشحن: $e')));
      }
    }
  }

  /// شحن جماعي بخطوتين: تأكيد ثم تنفيذ. يعرض النطاق (الكل أو نتائج البحث)
  /// قبل الكتابة، لأن الشحن الجماعي لا رجعة فيه.
  Future<void> _grantBulk() async {
    final coins = int.tryParse(_coins.text.trim()) ?? 0;
    if (coins <= 0) return;
    final days = int.tryParse(_days.text.trim()) ?? 0;
    final scope = _bulkAll ? 'كل المحافظ' : 'نتائج البحث';
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('شحن جماعي'),
        content: Text('سيُضاف $coins عملة إلى $scope'
            '${_bulkAll ? '' : ' («$_q»)'}.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('إلغاء')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('شحن')),
        ],
      ),
    );
    if (ok != true) return;
    try {
      final n = await widget.api
          .grantWalletBulk(coins, days, all: _bulkAll, q: _q);
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('تم شحن $n محفظة بـ $coins عملة')));
      }
      await _load();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('فشل الشحن الجماعي: $e')));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final rows = _rows;
    final totalCoins = (rows ?? const [])
        .fold<int>(0, (a, w) => a + (((w as Map)['balance'] as num?)?.toInt() ?? 0));
    final zeroCount = (rows ?? const [])
        .where((w) => (((w as Map)['balance'] as num?)?.toInt() ?? 0) == 0)
        .length;
    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(14, 14, 14, 6),
        child: GlassCard(
          padding: const EdgeInsets.all(12),
          child: Column(children: [
            Row(children: [
              Icon(Icons.account_balance_wallet_outlined,
                  color: XTheme.gold, size: 20),
              const SizedBox(width: 8),
              const Expanded(
                child: Text('محافظ الزوار',
                    style: TextStyle(fontWeight: FontWeight.w900, fontSize: 14)),
              ),
              Text('${rows?.length ?? 0}',
                  style: TextStyle(
                      fontWeight: FontWeight.w900,
                      color: XTheme.accent,
                      fontSize: 15)),
            ]),
            const SizedBox(height: 8),
            Row(children: [
              Expanded(
                child: _WalletStat(
                  label: 'إجمالي العملات',
                  value: '$totalCoins',
                  color: XTheme.gold,
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: _WalletStat(
                  label: 'رصيد صفر',
                  value: '$zeroCount',
                  color: zeroCount > 0 ? XTheme.danger : XTheme.textDim,
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: _WalletStat(
                  label: 'بلا صلاحية',
                  value:
                      '${(rows ?? const []).where((w) => (((w as Map)['expires_at'] as num?)?.toInt() ?? 0) == 0).length}',
                  color: XTheme.textDim,
                ),
              ),
            ]),
            const SizedBox(height: 10),
            TextField(
              controller: _search,
              onChanged: (v) => setState(() => _q = v.trim()),
              onSubmitted: (_) => _load(),
              decoration: InputDecoration(
                hintText: 'ابحث بمعرّف الجهاز أو اسم المستخدم أو IP',
                isDense: true,
                prefixIcon: const Icon(Icons.search, size: 18),
                suffixIcon: _q.isEmpty
                    ? null
                    : IconButton(
                        icon: const Icon(Icons.close, size: 18),
                        onPressed: () {
                          _search.clear();
                          setState(() => _q = '');
                          _load();
                        },
                      ),
              ),
            ),
          ]),
        ),
      ),
      Padding(
        padding: const EdgeInsets.fromLTRB(14, 8, 14, 6),
        child: GlassCard(
          padding: const EdgeInsets.all(12),
          child: Column(children: [
            Text(
              'شحن عملات لزائر بمعرّف جهازه. الزائر بلا حساب، فيُعرَّف بجهازه — '
              'انسخ المعرّف من القائمة أدناه أو من تبويب «الحظر».',
              style: TextStyle(color: XTheme.textDim, fontSize: 11.5),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: _dev,
              decoration: const InputDecoration(
                  hintText: 'معرّف الجهاز', isDense: true),
              textDirection: TextDirection.ltr,
            ),
            const SizedBox(height: 8),
            Row(children: [
              Expanded(
                child: TextField(
                  controller: _coins,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(
                      hintText: 'عدد العملات', isDense: true),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: TextField(
                  controller: _days,
                  keyboardType: TextInputType.number,
                  decoration: const InputDecoration(
                      hintText: 'أيام الصلاحية (0=بلا حد)', isDense: true),
                ),
              ),
            ]),
            const SizedBox(height: 10),
            Row(children: [
              Expanded(
                child: FilledButton.icon(
                  onPressed: _grant,
                  icon: const Icon(Icons.add_card, size: 18),
                  label: const Text('شحن الرصيد'),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: FilledButton.icon(
                  onPressed: _grantBulk,
                  style: FilledButton.styleFrom(
                      backgroundColor: XTheme.gold.withOpacity(.16),
                      foregroundColor: XTheme.gold),
                  icon: const Icon(Icons.groups_rounded, size: 18),
                  label: const Text('شحن للكل'),
                ),
              ),
            ]),
            const SizedBox(height: 6),
            InkWell(
              onTap: () => setState(() => _bulkAll = !_bulkAll),
              borderRadius: BorderRadius.circular(8),
              child: Padding(
                padding: const EdgeInsets.symmetric(vertical: 4, horizontal: 2),
                child: Row(children: [
                  Icon(
                      _bulkAll
                          ? Icons.check_box_rounded
                          : Icons.check_box_outline_blank_rounded,
                      size: 20,
                      color: _bulkAll ? XTheme.accent : XTheme.textDim),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      _bulkAll
                          ? '«شحن للكل» يشمل كل المحافظ'
                          : '«شحن للكل» يقصر على نتائج البحث الحالية',
                      style: TextStyle(
                          color: XTheme.textDim, fontSize: 11.5),
                    ),
                  ),
                ]),
              ),
            ),
          ]),
        ),
      ),
      Expanded(
        child: rows == null
            ? Center(child: CircularProgressIndicator(color: XTheme.accent))
            : rows.isEmpty
                ? Center(
                    child: Text(
                        _q.isEmpty ? 'لا محافظ بعد' : 'لا نتائج مطابقة للبحث',
                        style: TextStyle(color: XTheme.textDim)))
                : RefreshIndicator(
                    onRefresh: _load,
                    color: XTheme.accent,
                    child: ListView.builder(
                      padding: const EdgeInsets.fromLTRB(14, 0, 14, 24),
                      itemCount: rows.length,
                      itemBuilder: (context, i) => _walletCard(rows[i]),
                    ),
                  ),
      ),
    ]);
  }

  Widget _walletCard(dynamic row) {
    final w = row as Map;
    final dev = '${w['device_id']}';
    final bal = (w['balance'] as num?)?.toInt() ?? 0;
    final exp = (w['expires_at'] as num?)?.toInt() ?? 0;
    final expired = exp > 0 && exp <= DateTime.now().millisecondsSinceEpoch;
    final username = '${w['username'] ?? ''}';
    final ip = '${w['last_ip'] ?? ''}';
    final ver = '${w['app_version'] ?? ''}';
    final lastSeen = (w['last_seen'] as String?) ?? '';
    final seen = lastSeen.isEmpty
        ? ''
        : lastSeen.split('T').first;
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: GlassCard(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Icon(Icons.account_balance_wallet_outlined,
                color: bal > 0 ? XTheme.gold : XTheme.textDim, size: 20),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                dev,
                style: const TextStyle(
                    fontSize: 11.5, fontWeight: FontWeight.w700),
                textDirection: TextDirection.ltr,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
              decoration: BoxDecoration(
                  color: (bal > 0 ? XTheme.gold : XTheme.danger).withOpacity(.12),
                  borderRadius: BorderRadius.circular(20)),
              child: Text('$bal',
                  style: TextStyle(
                      fontWeight: FontWeight.w900,
                      fontSize: 15,
                      color: bal > 0 ? XTheme.gold : XTheme.danger)),
            ),
          ]),
          const SizedBox(height: 4),
          Wrap(spacing: 6, runSpacing: 4, children: [
            if (username.isNotEmpty)
              _Chip(icon: Icons.person_outline, text: username),
            if (ver.isNotEmpty && ver != 'null')
              _Chip(icon: Icons.android, text: 'إصدار $ver'),
            if (ip.isNotEmpty && ip != 'null')
              _Chip(icon: Icons.public, text: ip),
            if (seen.isNotEmpty)
              _Chip(icon: Icons.schedule, text: seen),
          ]),
          const SizedBox(height: 4),
          Row(children: [
            Icon(expired ? Icons.error_outline : Icons.event_available,
                size: 13,
                color: expired ? XTheme.danger : XTheme.textDim),
            const SizedBox(width: 4),
            Text(
              expired
                  ? 'منتهية الصلاحية'
                  : exp > 0
                      ? 'صالحة حتى ${DateTime.fromMillisecondsSinceEpoch(exp).toLocal().toString().split(' ').first}'
                      : 'بلا تاريخ انتهاء',
              style: TextStyle(
                  fontSize: 10.5,
                  color: expired ? XTheme.danger : XTheme.textDim),
            ),
          ]),
          const SizedBox(height: 2),
          Row(mainAxisAlignment: MainAxisAlignment.end, children: [
            IconButton(
              tooltip: 'نسخ معرّف الجهاز',
              onPressed: () => copyDeviceId(context, dev),
              icon: const Icon(Icons.copy_rounded, size: 18),
            ),
            IconButton(
              tooltip: 'شحن 5 عملات',
              onPressed: () async {
                await widget.api.grantWallet(dev, 5, 0);
                _load();
              },
              icon: const Icon(Icons.add, size: 18),
            ),
            IconButton(
              tooltip: 'إنقاص عملة',
              onPressed: () => _adjust(w, -1),
              icon: const Icon(Icons.remove, size: 18),
            ),
            IconButton(
              tooltip: 'تعديل المحفظة',
              onPressed: () => _edit(w),
              icon: const Icon(Icons.tune, size: 18),
            ),
            IconButton(
              tooltip: 'حذف المحفظة',
              onPressed: () => _delete(w),
              icon: Icon(Icons.delete_outline, size: 18, color: XTheme.danger),
            ),
          ]),
        ]),
      ),
    );
  }

  /// إنقاص/زيادة بجرعة — الرصيد لا ينزل تحت الصفر على الخادم.
  Future<void> _adjust(Map<dynamic, dynamic> w, int delta) async {
    try {
      await widget.api.adjustWallet('${w['device_id']}', delta);
      await _load();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('فشل التعديل: $e')));
      }
    }
  }

  /// تعديل صريح: تعيين الرصيد والصلاحية لقيم محددة (لا جمع).
  Future<void> _edit(Map<dynamic, dynamic> w) async {
    final bal = (w['balance'] as num?)?.toInt() ?? 0;
    final coins = TextEditingController(text: '$bal');
    final days = TextEditingController(text: '0');
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: const Text('تعديل المحفظة'),
        content: Column(mainAxisSize: MainAxisSize.min, children: [
          Text('${w['device_id']}',
              style: const TextStyle(fontSize: 11),
              textDirection: TextDirection.ltr),
          const SizedBox(height: 12),
          TextField(
            controller: coins,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(
                labelText: 'الرصيد (قيمة محددة)', isDense: true),
          ),
          const SizedBox(height: 8),
          TextField(
            controller: days,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(
                labelText: 'تمديد الصلاحية (أيام، 0=بلا حد)', isDense: true),
          ),
        ]),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('إلغاء')),
          FilledButton(onPressed: () => Navigator.pop(c, true), child: const Text('حفظ')),
        ],
      ),
    );
    final vCoins = int.tryParse(coins.text.trim()) ?? 0;
    final vDays = int.tryParse(days.text.trim()) ?? 0;
    coins.dispose();
    days.dispose();
    if (ok != true) return;
    try {
      await widget.api.editWallet('${w['device_id']}', vCoins, vDays);
      await _load();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('فشل الحفظ: $e')));
      }
    }
  }

  /// حذف المحفظة بالكامل — الزائر يفقد رصيده المدفوع.
  Future<void> _delete(Map<dynamic, dynamic> w) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        title: const Text('حذف المحفظة؟'),
        content: Text('سيُحذف رصيد الجهاز ${w['device_id']} نهائياً.',
            style: const TextStyle(fontSize: 12)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: const Text('إلغاء')),
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: XTheme.danger),
            onPressed: () => Navigator.pop(c, true),
            child: const Text('حذف'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    try {
      await widget.api.deleteWallet('${w['device_id']}');
      await _load();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('فشل الحذف: $e')));
      }
    }
  }
}

// ============ الدردشة ============

/// إشراف المالك على الدردشة: الرسائل، الأقسام، الكتم والطرد.
///
/// كل الإجراءات تُسجَّل في سجل الأمان، والمالك لا يمكن تقييده. الأقسام
/// تُحفظ ضمن إعدادات التطبيق نفسها، فتبقى بعد إعادة النشر.
class _ChatTab extends StatefulWidget {
  const _ChatTab({required this.api});
  final Api api;

  @override
  State<_ChatTab> createState() => _ChatTabState();
}

class _ChatTabState extends State<_ChatTab>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 3, vsync: this)
    ..addListener(() => setState(() {}));

  List<dynamic>? _messages;
  List<ChatAction>? _actions;
  XSettings? _settings;
  bool _saving = false;
  String? _msg;
  String _room = '';

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _tabs.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final results = await Future.wait([
        widget.api.ownerChatMessages(room: _room),
        widget.api.ownerChatActions(),
        widget.api.ownerSettings(),
      ]);
      if (!mounted) return;
      setState(() {
        _messages = results[0] as List;
        _actions = results[1] as List<ChatAction>;
        _settings = XSettings.fromJson(
            (results[2] as Map)['settings'] as Map<String, dynamic>);
      });
    } catch (_) {
      if (mounted) {
        setState(() {
          _messages = _messages ?? [];
          _actions = _actions ?? [];
        });
      }
    }
  }

  List<ChatRoom> get _rooms => _settings?.chatRooms ?? const [];

  void _toast(String m) {
    if (!mounted) return;
    ScaffoldMessenger.of(context)
      ..clearSnackBars()
      ..showSnackBar(SnackBar(
        content: Text(m),
        behavior: SnackBarBehavior.floating,
        backgroundColor: XTheme.surface2,
      ));
  }

  /// حفظ إعدادات الدردشة وحدها — لا يمس بقية الإعدادات.
  Future<void> _saveChat({String? msg}) async {
    final s = _settings;
    if (s == null) return;
    setState(() {
      _saving = true;
      _msg = null;
    });
    try {
      final r = await widget.api.saveSettings({
        'chatEnabled': s.chatEnabled,
        'chatReadOnly': s.chatReadOnly,
        'chatTheme': s.chatTheme,
        'chatWelcome': s.chatWelcome,
        'chatMaxLength': s.chatMaxLength,
        'chatImagesEnabled': s.chatImagesEnabled,
        'chatWriteScope': s.chatWriteScope,
        'chatMediaScope': s.chatMediaScope,
        'chatMaxMediaMb': s.chatMaxMediaMb,
        'chatMediaSeconds': s.chatMediaSeconds,
        'chatPollMs': s.chatPollMs,
        'chatRooms': s.chatRooms
            .map((r) => {'id': r.id, 'name': r.name, 'icon': r.icon})
            .toList(),
      });
      if (!mounted) return;
      setState(() {
        _settings =
            XSettings.fromJson(r['settings'] as Map<String, dynamic>);
        _msg = msg ?? 'تم الحفظ';
      });
    } catch (_) {
      if (mounted) setState(() => _msg = 'فشل الحفظ');
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_settings == null) {
      return Center(child: CircularProgressIndicator(color: XTheme.accent));
    }
    return Column(children: [
      TabBar(
        controller: _tabs,
        labelColor: XTheme.accent,
        unselectedLabelColor: XTheme.textDim,
        indicatorColor: XTheme.accent,
        labelStyle: const TextStyle(fontWeight: FontWeight.w800, fontSize: 12.5),
        tabs: const [
          Tab(text: 'الرسائل'),
          Tab(text: 'الأعضاء المقيّدون'),
          Tab(text: 'الإعدادات'),
        ],
      ),
      if (_msg != null)
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: Text(_msg!,
              style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w800,
                  color: _msg == 'تم الحفظ' ? XTheme.ok : XTheme.danger)),
        ),
      Expanded(
        child: TabBarView(
          controller: _tabs,
          children: [_messagesView(), _restrictionsView(), _settingsView()],
        ),
      ),
    ]);
  }

  // ── الرسائل: مراجعة وحذف ──

  Widget _messagesView() {
    final list = _messages ?? const [];
    return Column(children: [
      Container(
        height: 40,
        margin: const EdgeInsets.fromLTRB(14, 10, 14, 0),
        child: ListView(
          scrollDirection: Axis.horizontal,
          reverse: true,
          children: [
            _roomChip('', 'الكل'),
            for (final r in _rooms) _roomChip(r.id, r.name),
          ],
        ),
      ),
      const SizedBox(height: 8),
      Expanded(
        child: list.isEmpty
            ? Center(
                child: Text('لا رسائل',
                    style: TextStyle(color: XTheme.textDim)))
            : RefreshIndicator(
                onRefresh: _load,
                color: XTheme.accent,
                child: ListView.builder(
                  padding: const EdgeInsets.fromLTRB(14, 0, 14, 24),
                  itemCount: list.length,
                  itemBuilder: (context, i) => _messageCard(list[i]),
                ),
              ),
      ),
    ]);
  }

  Widget _roomChip(String id, String name) => Padding(
        padding: const EdgeInsets.only(left: 8),
        child: GestureDetector(
          onTap: () async {
            setState(() => _room = id);
            await _load();
          },
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 14),
            alignment: Alignment.center,
            decoration: BoxDecoration(
              gradient: _room == id ? XTheme.gradient : null,
              color: _room == id ? null : XTheme.surface2,
              borderRadius: BorderRadius.circular(30),
            ),
            child: Text(name,
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w800,
                  color: _room == id ? Colors.white : XTheme.text,
                )),
          ),
        ),
      );

  Widget _messageCard(dynamic m) {
    final kind = '${m['kind'] ?? 'text'}';
    final media = '${m['mediaUrl'] ?? ''}';
    final deleted = m['deleted'] == true;
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: GlassCard(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        child: Row(children: [
          Icon(
            kind == 'image'
                ? Icons.image_outlined
                : (kind == 'audio'
                    ? Icons.mic_none
                    : (kind == 'video'
                        ? Icons.videocam_outlined
                        : Icons.chat_bubble_outline)),
            size: 19,
            color: deleted ? XTheme.textDim : XTheme.cyan,
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(m['nickname']?.toString().isNotEmpty == true
                    ? m['nickname']
                    : (m['username'] ?? 'عضو'),
                    style: const TextStyle(
                        fontWeight: FontWeight.w800, fontSize: 12.5)),
                const SizedBox(height: 2),
                Text(
                  deleted
                      ? 'محذوفة'
                      : (media.isNotEmpty
                          ? 'وسيط ($kind)'
                          : (m['body'] ?? '').toString()),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                      fontSize: 12,
                      color: deleted ? XTheme.textDim : XTheme.text),
                ),
                if ('${m['roomId']}'.isNotEmpty)
                  Text('قسم: ${m['roomId']}',
                      style: TextStyle(
                          fontSize: 10, color: XTheme.textDim)),
              ],
            ),
          ),
          // أزرار الإشراف على كاتب الرسالة
          PopupMenuButton<String>(
            tooltip: 'إجراء',
            icon: Icon(Icons.more_vert, size: 18, color: XTheme.textDim),
            onSelected: (v) async {
              final uid = '${m['userId']}';
              if (v == 'delete') {
                await widget.api.ownerDeleteChatMessage('${m['id']}');
                await _load();
                return;
              }
              await _restrictDialog(uid,
                  kind: v == 'mute' ? 'mute' : 'kick');
            },
            itemBuilder: (_) => [
              const PopupMenuItem(value: 'mute', child: Text('كتم العضو')),
              const PopupMenuItem(value: 'kick', child: Text('طرد من الدردشة')),
              if (!deleted)
                const PopupMenuItem(value: 'delete', child: Text('حذف الرسالة')),
            ],
          ),
        ]),
      ),
    );
  }

  /// حوار كتم/طرد: نطاق (كل الأقسام أو قسم)، مدة، وسبب يُعرض للعضو.
  Future<void> _restrictDialog(String userId, {required String kind}) async {
    String room = '';
    String reason = '';
    int minutes = 0;
    final isMute = kind == 'mute';
    await showDialog<void>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setD) => AlertDialog(
          backgroundColor: XTheme.surface,
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
          title: Text(isMute ? 'كتم عضو' : 'طرد من الدردشة',
              style: const TextStyle(fontWeight: FontWeight.w900)),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                isMute
                    ? 'المكتوم لا يستطيع الكتابة، ويمكنه القراءة.'
                    : 'المطرود لا يستطيع الكتابة في القسم المحدد.',
                style: TextStyle(fontSize: 12, color: XTheme.textDim),
              ),
              const SizedBox(height: 12),
              Text('النطاق',
                  style: TextStyle(fontSize: 11.5, color: XTheme.textDim)),
              const SizedBox(height: 6),
              DropdownButtonFormField<String>(
                initialValue: room,
                items: [
                  const DropdownMenuItem(value: '', child: Text('كل الأقسام')),
                  for (final r in _rooms)
                    DropdownMenuItem(value: r.id, child: Text(r.name)),
                ],
                onChanged: (v) => setD(() => room = v ?? ''),
              ),
              const SizedBox(height: 12),
              Text('المدة',
                  style: TextStyle(fontSize: 11.5, color: XTheme.textDim)),
              const SizedBox(height: 6),
              Wrap(spacing: 6, children: [
                for (final opt in const [
                  (0, 'دائم'),
                  (60, 'ساعة'),
                  (1440, 'يوم'),
                  (10080, 'أسبوع'),
                ])
                  ChoiceChip(
                    label: Text(opt.$2,
                        style: const TextStyle(fontSize: 11.5)),
                    selected: minutes == opt.$1,
                    onSelected: (_) => setD(() => minutes = opt.$1),
                  ),
              ]),
              const SizedBox(height: 12),
              TextField(
                maxLength: 120,
                decoration: const InputDecoration(
                  hintText: 'سبب (يظهر للعضو)',
                  isDense: true,
                  counterText: '',
                ),
                onChanged: (v) => reason = v,
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: Text('إلغاء', style: TextStyle(color: XTheme.textDim)),
            ),
            FilledButton(
              onPressed: () async {
                Navigator.pop(ctx);
                try {
                  await widget.api.ownerChatAction(
                    userId: userId,
                    kind: kind,
                    room: room,
                    reason: reason.trim(),
                    minutes: minutes,
                  );
                  await _load();
                  _toast(isMute ? 'تم الكتم' : 'تم الطرد');
                } catch (e) {
                  _toast('فشل الإجراء: $e');
                }
              },
              style: FilledButton.styleFrom(
                  backgroundColor:
                      isMute ? XTheme.accent : XTheme.danger),
              child: Text(isMute ? 'كتم' : 'طرد'),
            ),
          ],
        ),
      ),
    );
  }

  // ── الأعضاء المقيّدون ──

  Widget _restrictionsView() {
    final list = _actions ?? const <ChatAction>[];
    if (list.isEmpty) {
      return Center(
          child: Text('لا عقوبات مسجّلة',
              style: TextStyle(color: XTheme.textDim)));
    }
    return RefreshIndicator(
      onRefresh: _load,
      color: XTheme.accent,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(14, 12, 14, 24),
        itemCount: list.length,
        itemBuilder: (context, i) {
          final a = list[i];
          final color = a.active
              ? (a.isMute ? XTheme.accent : XTheme.danger)
              : XTheme.textDim;
          return Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: GlassCard(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              child: Row(children: [
                Icon(a.isMute ? Icons.volume_off : Icons.block,
                    size: 19, color: color),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        '${a.username.isEmpty ? a.userId : a.username} • '
                        '${a.isMute ? 'كتم' : 'طرد'}',
                        style: const TextStyle(
                            fontWeight: FontWeight.w800, fontSize: 12.5),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        '${a.roomId.isEmpty ? 'كل الأقسام' : a.roomId} • '
                        '${a.isPermanent ? 'دائم' : 'حتى ${_untilText(a.until)}'}',
                        style: TextStyle(
                            fontSize: 11, color: XTheme.textDim),
                      ),
                      if (a.reason.isNotEmpty)
                        Text(a.reason,
                            style: TextStyle(
                                fontSize: 11, color: XTheme.textDim)),
                    ],
                  ),
                ),
                StatusPill(a.active ? 'سارٍ' : 'منتهي', color: color),
                IconButton(
                  tooltip: 'رفع العقوبة',
                  onPressed: () async {
                    await widget.api.ownerClearChatAction(a.userId,
                        kind: a.kind);
                    await _load();
                  },
                  icon: Icon(Icons.undo, size: 18, color: XTheme.ok),
                ),
              ]),
            ),
          );
        },
      ),
    );
  }

  static String _untilText(int until) {
    final d = DateTime.fromMillisecondsSinceEpoch(until);
    final left = d.difference(DateTime.now());
    if (left.isNegative) return 'منتهية';
    if (left.inDays >= 1) return '${left.inDays} يوم';
    if (left.inHours >= 1) return '${left.inHours} ساعة';
    return '${left.inMinutes} دقيقة';
  }

  // ── إعدادات الدردشة ──

  Widget _settingsView() {
    final s = _settings!;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        GlassCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SectionTitle('حالة الدردشة', icon: Icons.tune),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text('تشغيل الدردشة',
                    style: TextStyle(fontWeight: FontWeight.w700)),
                subtitle: Text('إيقافها يخفيها عن كل الأعضاء فوراً',
                    style: TextStyle(color: XTheme.textDim, fontSize: 11)),
                value: s.chatEnabled,
                activeColor: XTheme.cyan,
                onChanged: (v) => setState(() => s.chatEnabled = v),
              ),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text('القراءة فقط',
                    style: TextStyle(fontWeight: FontWeight.w700)),
                subtitle: Text('يمنع الكتابة عن الجميع عدا المالك',
                    style: TextStyle(color: XTheme.textDim, fontSize: 11)),
                value: s.chatReadOnly,
                activeColor: XTheme.cyan,
                onChanged: (v) => setState(() => s.chatReadOnly = v),
              ),
              SwitchListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text('السماح برفع الصور',
                    style: TextStyle(fontWeight: FontWeight.w700)),
                subtitle: Text('الصور متاحة لكل من يستطيع الكتابة',
                    style: TextStyle(color: XTheme.textDim, fontSize: 11)),
                value: s.chatImagesEnabled,
                activeColor: XTheme.cyan,
                onChanged: (v) => setState(() => s.chatImagesEnabled = v),
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        GlassCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SectionTitle('من يشارك', icon: Icons.group_outlined),
              Text('من يستطيع الكتابة',
                  style: TextStyle(fontSize: 11.5, color: XTheme.textDim)),
              const SizedBox(height: 6),
              DropdownButtonFormField<String>(
                initialValue: s.chatWriteScope,
                decoration: const InputDecoration(isDense: true),
                items: const [
                  DropdownMenuItem(
                      value: 'all', child: Text('الجميع (زوار ومسجّلون)')),
                  DropdownMenuItem(
                      value: 'registered', child: Text('المسجّلون فقط')),
                  DropdownMenuItem(
                      value: 'subscribers', child: Text('المشتركون فقط')),
                ],
                onChanged: (v) =>
                    setState(() => s.chatWriteScope = v ?? 'registered'),
              ),
              const SizedBox(height: 12),
              Text('من يرسل الصوت والفيديو',
                  style: TextStyle(fontSize: 11.5, color: XTheme.textDim)),
              const SizedBox(height: 6),
              DropdownButtonFormField<String>(
                initialValue: s.chatMediaScope,
                decoration: const InputDecoration(isDense: true),
                items: const [
                  DropdownMenuItem(
                      value: 'subscribers', child: Text('المشتركون فقط')),
                  DropdownMenuItem(value: 'none', child: Text('موقوف')),
                ],
                onChanged: (v) =>
                    setState(() => s.chatMediaScope = v ?? 'subscribers'),
              ),
              const SizedBox(height: 14),
              _numField('أقصى طول للرسالة (حرف)', s.chatMaxLength, (v) {
                setState(() => s.chatMaxLength = v);
              }),
              _numField('أقصى حجم للوسيط (MB)', s.chatMaxMediaMb, (v) {
                setState(() => s.chatMaxMediaMb = v);
              }),
              _numField('أقصى مدة مقطع (ثانية)', s.chatMediaSeconds, (v) {
                setState(() => s.chatMediaSeconds = v);
              }),
              _numField('زمن التحديث (مللي ثانية)', s.chatPollMs, (v) {
                setState(() => s.chatPollMs = v);
              }),
              const SizedBox(height: 6),
              Text(
                'زمن التحديث يحدد كل كم يطلب التطبيق الرسائل الجديدة. القيمة '
                'الأكبر توفّر بطارية وشبكة، والأصغر تجعل الوصول أسرع.',
                style: TextStyle(fontSize: 11, color: XTheme.textDim),
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        GlassCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SectionTitle('المظهر والترحيب', icon: Icons.palette_outlined),
              DropdownButtonFormField<String>(
                initialValue: s.chatTheme,
                decoration: const InputDecoration(
                    labelText: 'سمة الفقاعات', isDense: true),
                items: const [
                  DropdownMenuItem(value: 'bubble', child: Text('فقاعات')),
                  DropdownMenuItem(value: 'classic', child: Text('كلاسيكي')),
                  DropdownMenuItem(value: 'neon', child: Text('نيون')),
                  DropdownMenuItem(value: 'dark', child: Text('داكن')),
                ],
                onChanged: (v) => setState(() => s.chatTheme = v ?? 'bubble'),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: TextEditingController(text: s.chatWelcome)
                  ..selection = TextSelection.collapsed(
                      offset: s.chatWelcome.length),
                maxLength: 300,
                maxLines: 3,
                decoration: const InputDecoration(
                  labelText: 'رسالة ترحيب تظهر أعلى الدردشة',
                  isDense: true,
                ),
                onChanged: (v) => s.chatWelcome = v,
              ),
            ],
          ),
        ),
        const SizedBox(height: 12),
        GlassCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SectionTitle('أقسام الدردشة',
                  icon: Icons.forum_outlined,
                  trailing: IconButton(
                    tooltip: 'إضافة قسم',
                    onPressed: _addRoomDialog,
                    icon: Icon(Icons.add_circle, color: XTheme.cyan),
                  )),
              if (s.chatRooms.isEmpty)
                Text('لا أقسام — أضف قسماً ليظهر للأعضاء',
                    style: TextStyle(fontSize: 12, color: XTheme.textDim)),
              for (var i = 0; i < s.chatRooms.length; i++)
                Padding(
                  padding: const EdgeInsets.only(bottom: 6),
                  child: Row(children: [
                    Icon(Icons.drag_indicator,
                        size: 18, color: XTheme.textDim),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text('${s.chatRooms[i].name}  ·  '
                          '${s.chatRooms[i].id}',
                          style: const TextStyle(
                              fontSize: 12.5, fontWeight: FontWeight.w700)),
                    ),
                    IconButton(
                      tooltip: 'تعديل',
                      onPressed: () => _addRoomDialog(index: i),
                      icon: Icon(Icons.edit_outlined,
                          size: 17, color: XTheme.cyan),
                    ),
                    IconButton(
                      tooltip: 'حذف',
                      onPressed: () => setState(() {
                        s.chatRooms.removeAt(i);
                      }),
                      icon: Icon(Icons.delete_outline,
                          size: 17, color: XTheme.danger),
                    ),
                  ]),
                ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        SizedBox(
          width: double.infinity,
          child: FilledButton.icon(
            onPressed: _saving ? null : () => _saveChat(),
            icon: _saving
                ? const SizedBox(
                    width: 16, height: 16,
                    child: CircularProgressIndicator(
                        strokeWidth: 2, color: Colors.white))
                : const Icon(Icons.save_outlined, size: 18),
            label: const Text('حفظ إعدادات الدردشة',
                style: TextStyle(fontWeight: FontWeight.w900)),
            style: FilledButton.styleFrom(
              backgroundColor: XTheme.accent,
              padding: const EdgeInsets.symmetric(vertical: 14),
              shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(XTheme.rMd)),
            ),
          ),
        ),
        const SizedBox(height: 20),
      ],
    );
  }

  Widget _numField(String label, int value, ValueChanged<int> onChanged) =>
      Padding(
        padding: const EdgeInsets.only(top: 10),
        child: TextFormField(
          initialValue: '$value',
          keyboardType: TextInputType.number,
          decoration: InputDecoration(labelText: label, isDense: true),
          onChanged: (v) => onChanged(int.tryParse(v.trim()) ?? value),
        ),
      );

  /// إضافة قسم أو تعديله. المعرّف لاتيني قصير لأنه يُخزَّن في كل رسالة.
  Future<void> _addRoomDialog({int? index}) async {
    final s = _settings!;
    final existing = index == null ? null : s.chatRooms[index];
    final id = TextEditingController(text: existing?.id ?? '');
    final name = TextEditingController(text: existing?.name ?? '');
    var icon = existing?.icon ?? 'chat';
    final icons = const {
      'chat': 'محادثة',
      'build': 'صيانة',
      'memory': 'قطع',
      'store': 'بيع وشراء',
      'help': 'مساعدة',
      'sell': 'عروض',
    };
    await showDialog<void>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setD) => AlertDialog(
          backgroundColor: XTheme.surface,
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
          title: Text(index == null ? 'قسم جديد' : 'تعديل القسم',
              style: const TextStyle(fontWeight: FontWeight.w900)),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                controller: name,
                decoration: const InputDecoration(
                    labelText: 'اسم القسم', isDense: true),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: id,
                enabled: index == null,
                textDirection: TextDirection.ltr,
                decoration: const InputDecoration(
                  labelText: 'المعرّف (a-z، بلا مسافات)',
                  isDense: true,
                  helperText: 'يُستخدم داخلياً ويظهر في الروابط',
                ),
              ),
              const SizedBox(height: 10),
              DropdownButtonFormField<String>(
                initialValue: icon,
                decoration: const InputDecoration(
                    labelText: 'الأيقونة', isDense: true),
                items: [
                  for (final e in icons.entries)
                    DropdownMenuItem(value: e.key, child: Text(e.value)),
                ],
                onChanged: (v) => setD(() => icon = v ?? 'chat'),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: Text('إلغاء', style: TextStyle(color: XTheme.textDim)),
            ),
            FilledButton(
              onPressed: () {
                final rid = id.text.trim().toLowerCase();
                final rname = name.text.trim();
                if (rname.isEmpty ||
                    !RegExp(r'^[a-z0-9_]{2,20}$').hasMatch(rid)) {
                  setD(() {});
                  return;
                }
                setState(() {
                  final room = ChatRoom(id: rid, name: rname, icon: icon);
                  if (index == null) {
                    // منع التكرار: معرّف مكرر يجعل رسائل قسمين تختلط.
                    if (!s.chatRooms.any((r) => r.id == rid)) {
                      s.chatRooms.add(room);
                    }
                  } else {
                    s.chatRooms[index] = room;
                  }
                });
                Navigator.pop(ctx);
              },
              style: FilledButton.styleFrom(backgroundColor: XTheme.accent),
              child: const Text('حفظ'),
            ),
          ],
        ),
      ),
    );
  }
}

// ============ أمان اللوحة ============

/// قسم أمان لوحة المالك — قفل البصمة وإنهاء جلسة اللوحة.
///
/// الجلسة هنا منفصلة تماماً عن جلسة المستخدم العادي، ولها سرّها المستقل في
/// الخادم. «إنهاء الجلسة» يمحو الرمز المحلي وختم الفتح معاً، فلا يبقى أثر
/// يصلح لفتح اللوحة إن فُقد الهاتف.
class _OwnerPanelSecurity extends StatefulWidget {
  final Api api;
  final Store store;
  const _OwnerPanelSecurity({required this.api, required this.store});

  @override
  State<_OwnerPanelSecurity> createState() => _OwnerPanelSecurityState();
}

class _OwnerPanelSecurityState extends State<_OwnerPanelSecurity> {
  bool? _available;
  bool _enabled = false;
  String? _msg;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final available = await BiometricLock.available;
    final enabled = await BiometricLock.enabled;
    if (!mounted) return;
    setState(() {
      _available = available;
      _enabled = enabled;
    });
  }

  Future<void> _toggle(bool v) async {
    if (v) {
      // لا نفعّل القفل بلا تحقق ناجح أولاً — وإلا أقفل المالك نفسه خارج
      // اللوحة إن لم تكن بصمته مسجّلة فعلاً.
      final ok = await BiometricLock.authenticate(
          reason: 'تأكيد تفعيل قفل البصمة على لوحة المالك');
      if (!ok) {
        setState(() => _msg = 'لم ينجح التحقق — لم يُفعَّل القفل');
        return;
      }
    }
    await BiometricLock.setEnabled(v);
    if (!mounted) return;
    setState(() {
      _enabled = v;
      _msg = v ? 'قفل البصمة مفعّل' : 'قفل البصمة موقوف';
    });
  }

  Future<void> _logout() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('إنهاء جلسة اللوحة؟',
            style: TextStyle(fontWeight: FontWeight.w900, fontSize: 16)),
        content: const Text(
            'ستحتاج اسم المستخدم وكلمة المرور للدخول مرة أخرى. '
            'ستُغلق كل شاشات المالك وتعود للتصفح كزائر.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('إلغاء')),
          FilledButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('إنهاء')),
        ],
      ),
    );
    if (ok != true) return;
    // إنهاء كلّ جلسات المالك والمستخدم، وتوليد تثبيت جديد لإلغاء وصول
    // الدورات المفتوحة — المنح مربوطة بالتثبيت لا بالحساب.
    if (!mounted) return;
    // عودة كاملة للإقلاع: تُعيد تهيئة كل الشاشات والبيانات كزائر.
    await logoutToGuest(context, widget.api, widget.store);
  }

  @override
  Widget build(BuildContext context) {
    final available = _available ?? false;
    return GlassCard(
      accent: XTheme.cyan,
      padding: const EdgeInsets.fromLTRB(18, 12, 18, 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionTitle('أمان اللوحة', icon: Icons.shield_moon_outlined),
          Text(
            'جلسة اللوحة منفصلة عن حسابك العادي، وكل ردودها مشفّرة بمفتاح '
            'مشتق من الجلسة نفسها.',
            style:
                TextStyle(color: XTheme.textDim, fontSize: 11.5, height: 1.6),
          ),
          const SizedBox(height: 4),
          if (available)
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('قفل بالبصمة',
                  style:
                      TextStyle(fontWeight: FontWeight.w700, fontSize: 14)),
              subtitle: Text('يُطلب عند كل فتح للوحة',
                  style: TextStyle(color: XTheme.textDim, fontSize: 11)),
              value: _enabled,
              onChanged: _toggle,
              activeColor: XTheme.cyan,
            )
          else
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 8),
              child: Text(
                'لا توجد بصمة مسجّلة على هذا الجهاز — سجّلها في إعدادات '
                'الهاتف ثم أعد المحاولة.',
                style: TextStyle(color: XTheme.textDim, fontSize: 11.5),
              ),
            ),
          if (_msg != null)
            Padding(
              padding: const EdgeInsets.only(top: 2, bottom: 4),
              child: Text(_msg!,
                  style: const TextStyle(color: XTheme.ok, fontSize: 12)),
            ),
          const SizedBox(height: 6),
          SizedBox(
            width: double.infinity,
            child: OutlinedButton.icon(
              onPressed: _logout,
              icon: const Icon(Icons.logout_rounded, size: 18),
              label: const Text('إنهاء جلسة اللوحة',
                  style: TextStyle(fontWeight: FontWeight.w800)),
              style: OutlinedButton.styleFrom(
                foregroundColor: XTheme.danger,
                side: BorderSide(color: XTheme.danger.withOpacity(.45)),
                padding: const EdgeInsets.symmetric(vertical: 13),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(XTheme.rMd)),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// ============ الدورات ============

/// إدارة الأكاديمية: دورات، فيديوهات، مفاتيح، ومشتركون.
///
/// كل تغيير هنا يذهب للخادم ثم يُعاد الجلب منه. لا نحدّث الحالة محلياً
/// تفاؤلاً: مصدر الحقيقة واحد، وانعكاس التغيير في التطبيق يعتمد على أن
/// الخادم هو من يعرف الحقيقة لا على ما نعرضه نحن.
class _CoursesTab extends StatefulWidget {
  const _CoursesTab({required this.api});
  final Api api;

  @override
  State<_CoursesTab> createState() => _CoursesTabState();
}

class _CoursesTabState extends State<_CoursesTab>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 3, vsync: this)
    ..addListener(() => setState(() {}));

  List<dynamic> _courses = const [];
  List<dynamic> _keys = const [];
  List<dynamic> _subs = const [];
  bool _loading = true;
  String? _msg;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _tabs.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    try {
      final r = await widget.api.ownerCourses();
      if (!mounted) return;
      setState(() {
        _courses = (r['courses'] as List?) ?? const [];
        _keys = (r['keys'] as List?) ?? const [];
        _subs = (r['subscribers'] as List?) ?? const [];
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _msg = e is ApiException ? e.message : 'تعذر تحميل بيانات الدورات';
      });
    }
  }

  void _toast(String m) {
    if (!mounted) return;
    setState(() => _msg = m);
    ScaffoldMessenger.of(context)
      ..clearSnackBars()
      ..showSnackBar(SnackBar(
        content: Text(m),
        behavior: SnackBarBehavior.floating,
        backgroundColor: XTheme.surface2,
      ));
  }

  /// يختار صورة من المعرض ويعيد `(b64, mime)` أو null. يُستخدم للأغلفة
  /// والمصغّرات معاً حتى يمرّ الاختيار بمسار واحد: حرف واحد مختلف في الترميز
  /// يجعل الخادم يرد «لا بيانات».
  Future<({String b64, String mime})?> _pickImageB64() async {
    final picked = await ImagePicker()
        .pickImage(source: ImageSource.gallery, maxWidth: 1280, imageQuality: 88);
    if (picked == null) return null;
    final bytes = await picked.readAsBytes();
    if (bytes.isEmpty) return null;
    final n = picked.name.toLowerCase();
    final mime = n.endsWith('.png')
        ? 'image/png'
        : n.endsWith('.webp')
            ? 'image/webp'
            : 'image/jpeg';
    return (b64: base64Encode(bytes), mime: mime);
  }

  /// إنشاء دورة أو تعديلها.
  Future<void> _editCourse([Map<String, dynamic>? c]) async {
    final title = TextEditingController(text: '${c?['title'] ?? ''}');
    final subtitle = TextEditingController(text: '${c?['subtitle'] ?? ''}');
    final desc = TextEditingController(text: '${c?['description'] ?? ''}');
    final locked = ValueNotifier<bool>(c?['locked'] != false);
    final published = ValueNotifier<bool>(c?['published'] != false);
    final busy = ValueNotifier<bool>(false);
    // غلاف الدورة. `hasCover` يحمل الحالة الأولية من الخادم، و`coverB64` يُملأ
    // فقط عند اختيار صورة جديدة — فحفظ دورة قديمة لا يمسح غلافها القائم.
    final hasCover = ValueNotifier<bool>(
        '${c?['coverKey'] ?? c?['coverUrl'] ?? ''}'.isNotEmpty);
    String coverB64 = '';
    String coverMime = 'image/jpeg';

    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(XTheme.rLg)),
        title: Text(c == null ? 'دورة جديدة' : 'تعديل الدورة',
            style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w900)),
        content: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            TextField(
              controller: title,
              decoration: const InputDecoration(
                  labelText: 'اسم الدورة', border: OutlineInputBorder()),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: subtitle,
              decoration: const InputDecoration(
                  labelText: 'سطر توضيحي (اختياري)',
                  border: OutlineInputBorder()),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: desc,
              maxLines: 3,
              decoration: const InputDecoration(
                  labelText: 'وصف الدورة',
                  border: OutlineInputBorder()),
            ),
            const SizedBox(height: 10),
            // صورة الدورة: أول ما يراه المستخدم في الشبكة قبل أي نص.
            ValueListenableBuilder<bool>(
              valueListenable: hasCover,
              builder: (_, has, __) => Row(children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: busy.value ? null : () async {
                      final img = await _pickImageB64();
                      if (img == null) return;
                      coverB64 = img.b64;
                      coverMime = img.mime;
                      hasCover.value = true;
                    },
                    icon: const Icon(Icons.image_outlined, size: 18),
                    label: Text(has ? 'تغيير صورة الدورة' : 'صورة الدورة (غلاف)'),
                  ),
                ),
              ]),
            ),
            const SizedBox(height: 6),
            // مفتاح واحد: مقفلة أو مفتوحة. لا خيار «ظاهرة/مخفية» منفصل —
            // الدورة إما تُعرض للطلاب وإما لا، والقفل هو ما يحدّد ذلك.
            ValueListenableBuilder<bool>(
              valueListenable: locked,
              builder: (_, v, __) => SwitchListTile(
                contentPadding: EdgeInsets.zero,
                title: Text(v ? 'مقفلة — تحتاج مفتاحاً' : 'مفتوحة للجميع',
                    style: const TextStyle(fontSize: 13.5)),
                subtitle: Text(
                  v
                      ? 'يُدخل المشترك مفتاحاً فتفتح كل فيديوهات الدورة'
                      : 'كل الفيديوهات متاحة بلا مفتاح',
                  style: TextStyle(fontSize: 11.5, color: XTheme.textDim),
                ),
                value: v,
                onChanged: (b) => locked.value = b,
              ),
            ),
          ]),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text('إلغاء', style: TextStyle(color: XTheme.textDim)),
          ),
          ValueListenableBuilder<bool>(
            valueListenable: busy,
            builder: (_, b, __) => FilledButton(
              onPressed: b ? null : () async {
                if (title.text.trim().isEmpty) {
                  _toast('اسم الدورة مطلوب');
                  return;
                }
                busy.value = true;
                try {
                  final res = await widget.api.ownerSaveCourse(
                    id: '${c?['id'] ?? ''}',
                    title: title.text.trim(),
                    subtitle: subtitle.text.trim(),
                    description: desc.text.trim(),
                    locked: locked.value,
                    published: published.value,
                    sort: ((c?['sort'] as num?)?.toInt()) ?? 0,
                  );
                  // الصورة تُرفع بعد حفظ الدورة لأنها تحتاج معرّفها: الدورة
                  // الجديدة لا معرّف لها قبل أن يعيده الخادم.
                  if (coverB64.isNotEmpty) {
                    final id = '${res['id'] ?? c?['id'] ?? ''}';
                    if (id.isNotEmpty) {
                      await widget.api
                          .ownerUploadCourseCover(id, coverB64, coverMime);
                    }
                  }
                  if (!ctx.mounted) return;
                  Navigator.pop(ctx, true);
                } catch (e) {
                  busy.value = false;
                  _toast(e is ApiException ? e.message : 'فشل الحفظ');
                }
              },
              child: b
                  ? const SizedBox(
                      width: 16, height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2))
                  : const Text('حفظ'),
            ),
          ),
        ],
      ),
    );
    title.dispose();
    subtitle.dispose();
    desc.dispose();
    locked.dispose();
    hasCover.dispose();
    published.dispose();
    busy.dispose();
    if (ok == true) {
      _toast('تم الحفظ');
      await _load();
    }
  }

  Future<void> _deleteCourse(String id, String title) async {
    final ok = await _confirm('حذف الدورة؟',
        'ستُحذف «$title» مع كل فيديوهاتها ومفاتيحها. لا يمكن التراجع.');
    if (ok != true) return;
    try {
      await widget.api.ownerDeleteCourse(id);
      _toast('حُذفت الدورة');
      await _load();
    } catch (e) {
      _toast(e is ApiException ? e.message : 'فشل الحذف');
    }
  }

  /// إضافة فيديو: يختار المالك ملفاً من الجهاز فيُرفع مباشرة إلى دلو الدورات.
  ///
  /// الرفع multipart مساراً بمسار، فلا يمرّ الملف كاملاً في ذاكرة التطبيق.
  /// والحقول الوصفية تُرسل مع الطلب نفسه، فلا توجد حالة وسيطة تُفقد لو
  /// انقطع الاتصال.
  /// تعديل فيديو قائم: التصريح والنشر والعنوان. لا يمسّ الملف ولا رابطه.
  Future<void> _editVideo({
    required String courseId,
    required Object video,
  }) async {
    final v = video as Map;
    final title = TextEditingController(text: '${v['title'] ?? ''}');
    final desc = TextEditingController(text: '${v['description'] ?? ''}');
    final free = ValueNotifier<bool>('${v['mode']}' == 'free');
    final published = ValueNotifier<bool>(v['published'] != false);
    final busy = ValueNotifier<bool>(false);
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('تعديل الفيديو'),
        content: SizedBox(
          width: 420,
          child: SingleChildScrollView(
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              TextField(
                controller: title,
                decoration: const InputDecoration(labelText: 'عنوان الفيديو'),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: desc,
                maxLines: 3,
                decoration: const InputDecoration(labelText: 'وصف مختصر'),
              ),
              const SizedBox(height: 6),
              // خيار واحد لا أكثر: مقفل أو مفتوح. بقية الأوضاع (مجاني/منشور)
              // كانت تُشتّت المالك في ثلاث حالات لا فرق بينها عملياً: الفيديو
              // إما يُفتح أو يُقفل.
              ValueListenableBuilder<bool>(
                valueListenable: free,
                builder: (_, open, __) => SwitchListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text(open ? 'مفتوح' : 'مقفل',
                      style: const TextStyle(fontSize: 13.5)),
                  subtitle: Text(
                    open
                        ? 'يُشاهد بلا مفتاح دورة'
                        : 'يحتاج مفتاح فتح الدورة',
                    style: TextStyle(fontSize: 11.5, color: XTheme.textDim),
                  ),
                  value: open,
                  onChanged: (b) => free.value = b,
                ),
              ),
            ]),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text('إلغاء', style: TextStyle(color: XTheme.textDim)),
          ),
          ValueListenableBuilder<bool>(
            valueListenable: busy,
            builder: (_, b, __) => FilledButton(
              onPressed: b ? null : () async {
                if (title.text.trim().isEmpty) {
                  _toast('عنوان الفيديو مطلوب');
                  return;
                }
                busy.value = true;
                try {
                  // نبني الطلب من قيم الفيديو الحالية ونغيّر ما عدّله المالك
                  // فقط: إرسال حقول فارغة كان يمحو المدة والحجم والرابط.
                  await widget.api.ownerSaveVideo(
                    id: '${v['id']}',
                    courseId: courseId,
                    title: title.text.trim(),
                    objectKey: '${v['objectKey'] ?? v['object_key'] ?? ''}',
                    description: desc.text.trim(),
                    mime: '${v['mime'] ?? 'video/mp4'}',
                    durationS: (v['durationS'] as num?)?.toInt() ??
                        (v['duration_s'] as num?)?.toInt() ?? 0,
                    sizeBytes: (v['sizeBytes'] as num?)?.toInt() ??
                        (v['size_bytes'] as num?)?.toInt() ?? 0,
                    mode: free.value ? 'free' : 'locked',
                    sort: (v['sort'] as num?)?.toInt() ?? 0,
                    published: published.value,
                  );
                  if (!ctx.mounted) return;
                  Navigator.pop(ctx, true);
                } catch (e) {
                  busy.value = false;
                  _toast(e is ApiException ? e.message : 'فشل الحفظ');
                }
              },
              child: b
                  ? const SizedBox(
                      width: 16, height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2))
                  : const Text('حفظ'),
            ),
          ),
        ],
      ),
    );
    if (ok == true) await _load();
  }

  Future<void> _addVideo(String courseId) async {
    final title = TextEditingController();
    final desc = TextEditingController();
    final free = ValueNotifier<bool>(false);
    final busy = ValueNotifier<bool>(false);
    final progress = ValueNotifier<String>('');
    String? picked;
    XFile? thumb;
    XFile? cover;

    Future<String?> _toB64(XFile? file) async {
      if (file == null) return null;
      final bytes = await file.readAsBytes();
      return base64Encode(bytes);
    }

    String _imageMime(String name) {
      final n = name.toLowerCase();
      if (n.endsWith('.png')) return 'image/png';
      if (n.endsWith('.webp')) return 'image/webp';
      return 'image/jpeg';
    }

    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(XTheme.rLg)),
        title: const Text('إضافة فيديو',
            style: TextStyle(fontSize: 17, fontWeight: FontWeight.w900)),
        content: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            TextField(
              controller: title,
              decoration: const InputDecoration(
                  labelText: 'عنوان الفيديو', border: OutlineInputBorder()),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: desc,
              decoration: const InputDecoration(
                  labelText: 'وصف (اختياري)', border: OutlineInputBorder()),
            ),
            const SizedBox(height: 12),
            // اختيار الملف. نعرض اسمه بعد الاختيار كي يتأكد المالك من الصواب.
            ValueListenableBuilder<String>(
              valueListenable: progress,
              builder: (_, info, __) => Column(children: [
                OutlinedButton.icon(
                  onPressed: busy.value ? null : () async {
                    final x = await ImagePicker().pickVideo(
                        source: ImageSource.gallery);
                    if (x == null) return;
                    picked = x.path;
                    final mb = (await x.length()) / (1024 * 1024);
                    progress.value = '${x.name} — ${mb.toStringAsFixed(1)} MB';
                  },
                  icon: const Icon(Icons.video_file_outlined, size: 18),
                  label: Text(picked == null ? 'اختر ملف الفيديو' : 'تغيير الملف'),
                ),
                if (info.isNotEmpty)
                  Padding(
                    padding: const EdgeInsets.only(top: 8),
                    child: Text(info,
                        textAlign: TextAlign.center,
                        style: TextStyle(
                            fontSize: 11.5, color: XTheme.textDim)),
                  ),
              ]),
            ),
            const SizedBox(height: 10),
            Row(children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: busy.value ? null : () async {
                    final x = await ImagePicker().pickImage(
                      source: ImageSource.gallery,
                      maxWidth: 1024,
                      maxHeight: 1024,
                      imageQuality: 85,
                    );
                    if (x == null) return;
                    thumb = x;
                    if (ctx.mounted) (ctx as Element).markNeedsBuild();
                  },
                  icon: const Icon(Icons.image_outlined, size: 18),
                  label: Text(thumb == null ? 'مصغّرة الفيديو' : 'تم اختيار مصغّرة'),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: busy.value ? null : () async {
                    final x = await ImagePicker().pickImage(
                      source: ImageSource.gallery,
                      maxWidth: 1280,
                      maxHeight: 720,
                      imageQuality: 85,
                    );
                    if (x == null) return;
                    cover = x;
                    if (ctx.mounted) (ctx as Element).markNeedsBuild();
                  },
                  icon: const Icon(Icons.image, size: 18),
                  label: Text(cover == null ? 'غلاف الدورة' : 'تم اختيار غلاف'),
                ),
              ),
            ]),
            const SizedBox(height: 6),
            ValueListenableBuilder<bool>(
              valueListenable: free,
              builder: (_, open, __) => SwitchListTile(
                contentPadding: EdgeInsets.zero,
                title: Text(open ? 'مفتوح' : 'مقفل',
                    style: const TextStyle(fontSize: 13.5)),
                subtitle: Text(
                  open
                      ? 'يُشاهد بلا مفتاح دورة'
                      : 'يحتاج مفتاح فتح الدورة',
                  style: TextStyle(fontSize: 11.5, color: XTheme.textDim),
                ),
                value: open,
                onChanged: (b) => free.value = b,
              ),
            ),
            // أثناء الرفع: لا مفاتيح ولا إغلاق حتى ينتهي، فالإلغاء في المنتصف
            // يترك ملفاً نصف مرفوع على الخادم بلا فائدة.
            ValueListenableBuilder<bool>(
              valueListenable: busy,
              builder: (_, b, __) => !b
                  ? const SizedBox.shrink()
                  : Padding(
                      padding: const EdgeInsets.only(top: 10),
                      child: Column(children: [
                        const LinearProgressIndicator(color: XTheme.accent),
                        const SizedBox(height: 8),
                        Text('جاري الرفع… لا تغلق النافذة',
                            style: TextStyle(
                                fontSize: 11.5, color: XTheme.textDim)),
                      ]),
                    ),
            ),
          ]),
        ),
        actions: [
          TextButton(
            onPressed: busy.value ? null : () => Navigator.pop(ctx, false),
            child: Text('إلغاء', style: TextStyle(color: XTheme.textDim)),
          ),
          ValueListenableBuilder<bool>(
            valueListenable: busy,
            builder: (_, b, __) => FilledButton(
              onPressed: b ? null : () async {
                if (title.text.trim().isEmpty) {
                  _toast('عنوان الفيديو مطلوب');
                  return;
                }
                if (picked == null) {
                  _toast('اختر ملف الفيديو أولاً');
                  return;
                }
                busy.value = true;
                try {
                  final res = await widget.api.ownerUploadCourseVideo(
                    courseId: courseId,
                    title: title.text.trim(),
                    filePath: picked!,
                    description: desc.text.trim(),
                    mode: free.value ? 'free' : 'locked',
                    onProgress: (sent, total) {
                      // النسبة من الرفع الفعلي لا من تخمين: الأجزاء تُرسل
                      // تباعاً، فما يظهر هو ما وصل الخادم فعلاً.
                      final pct = total == 0 ? 0 : (sent * 100 / total).round();
                      final mb = sent / (1024 * 1024);
                      progress.value = 'يُرفع… $pct٪ ($mb من ${(total / 1048576).toStringAsFixed(1)} MB)';
                    },
                  );
                  final videoId = res['id']?.toString() ?? '';
                  if (videoId.isNotEmpty) {
                    final t = thumb;
                    if (t != null) {
                      final thumbB64 = await _toB64(t);
                      if (thumbB64 != null) {
                        await widget.api.ownerUploadCourseThumb(
                            videoId, thumbB64, _imageMime(t.name));
                      }
                    }
                    final cv = cover;
                    if (cv != null) {
                      final coverB64 = await _toB64(cv);
                      if (coverB64 != null) {
                        await widget.api.ownerUploadCourseCover(
                            courseId, coverB64, _imageMime(cv.name));
                      }
                    }
                  }
                  if (!ctx.mounted) return;
                  Navigator.pop(ctx, true);
                } catch (e) {
                  busy.value = false;
                  _toast(e is ApiException ? e.message : 'فشل رفع الفيديو');
                }
              },
              child: b
                  ? const SizedBox(
                      width: 16, height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2))
                  : const Text('رفع وإضافة'),
            ),
          ),
        ],
      ),
    );
    title.dispose();
    desc.dispose();
    free.dispose();
    busy.dispose();
    progress.dispose();
    if (ok == true) {
      _toast('أُضيف الفيديو');
      await _load();
    }
  }

  /// توليد مفتاح دورة — الكود يظهر مرة واحدة، فنعرضه في حوار منفصل.
  Future<void> _genKey(String courseId, String courseTitle) async {
    final label = TextEditingController();
    final uses = ValueNotifier<int>(1);
    final days = ValueNotifier<int>(0);
    final busy = ValueNotifier<bool>(false);
    final result = ValueNotifier<String>('');

    final done = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(XTheme.rLg)),
        title: Text('مفتاح لـ«$courseTitle»',
            style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w900)),
        content: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            ValueListenableBuilder<String>(
              valueListenable: result,
              builder: (_, code, __) => code.isEmpty
                  ? Text(
                      'المفتاح يُعرض مرة واحدة فقط ولا يُخزَّن في أي مكان. '
                      'انسخه وأرسله للمشترك قبل إغلاق النافذة.',
                      style: TextStyle(
                          fontSize: 12.2, color: XTheme.textDim, height: 1.6))
                  : Column(children: [
                      Container(
                        width: double.infinity,
                        padding: const EdgeInsets.all(14),
                        decoration: BoxDecoration(
                          color: XTheme.ok.withOpacity(.10),
                          borderRadius: BorderRadius.circular(XTheme.rMd),
                          border: Border.all(
                              color: XTheme.ok.withOpacity(.40)),
                        ),
                        child: SelectableText(
                          code,
                          textAlign: TextAlign.center,
                          style: const TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.w900,
                              letterSpacing: 1.2),
                        ),
                      ),
                      const SizedBox(height: 12),
                      SizedBox(
                        width: double.infinity,
                        child: FilledButton.icon(
                          onPressed: () async {
                            await Clipboard.setData(ClipboardData(text: code));
                            _toast('نُسخ المفتاح');
                          },
                          icon: const Icon(Icons.copy, size: 17),
                          label: const Text('نسخ المفتاح'),
                        ),
                      ),
                    ]),
            ),
            const SizedBox(height: 14),
            TextField(
              controller: label,
              decoration: const InputDecoration(
                  labelText: 'ملاحظة (اسم المشترك مثلاً)',
                  border: OutlineInputBorder()),
            ),
            const SizedBox(height: 10),
            ValueListenableBuilder<int>(
              valueListenable: uses,
              builder: (_, v, __) => DropdownButtonFormField<int>(
                initialValue: v,
                decoration: const InputDecoration(
                    labelText: 'عدد الأجهزة المسموح بها',
                    border: OutlineInputBorder()),
                items: const [
                  DropdownMenuItem(value: 1, child: Text('جهاز واحد')),
                  DropdownMenuItem(value: 5, child: Text('5 أجهزة')),
                  DropdownMenuItem(value: 25, child: Text('25 جهازاً')),
                  DropdownMenuItem(value: 100, child: Text('100 جهاز')),
                ],
                onChanged: (x) => uses.value = x ?? 1,
              ),
            ),
            const SizedBox(height: 10),
            ValueListenableBuilder<int>(
              valueListenable: days,
              builder: (_, v, __) => DropdownButtonFormField<int>(
                initialValue: v,
                decoration: const InputDecoration(
                    labelText: 'صلاحية المفتاح',
                    border: OutlineInputBorder()),
                items: const [
                  DropdownMenuItem(value: 0, child: Text('دائم لا ينتهي')),
                  DropdownMenuItem(value: 30, child: Text('شهر واحد')),
                  DropdownMenuItem(value: 90, child: Text('3 أشهر')),
                  DropdownMenuItem(value: 365, child: Text('سنة')),
                ],
                onChanged: (x) => days.value = x ?? 0,
              ),
            ),
          ]),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('إغلاق'),
          ),
          ValueListenableBuilder<String>(
            valueListenable: result,
            builder: (_, code, __) => code.isNotEmpty
                ? const SizedBox.shrink()
                : ValueListenableBuilder<bool>(
                    valueListenable: busy,
                    builder: (_, b, __) => FilledButton(
                      onPressed: b ? null : () async {
                        busy.value = true;
                        try {
                          final r = await widget.api.ownerCreateCourseKey(
                            courseId: courseId,
                            label: label.text.trim(),
                            maxUses: uses.value,
                            days: days.value,
                          );
                          result.value = '${r['code'] ?? ''}';
                          // نحدّث القوائم فوراً كي يرى المالك المفتاح الجديد
                          // في تبويب المفاتيح بلا إغلاق النافذة.
                          await _load();
                        } catch (e) {
                          _toast(e is ApiException ? e.message : 'فشل التوليد');
                        } finally {
                          busy.value = false;
                        }
                      },
                      child: b
                          ? const SizedBox(
                              width: 16, height: 16,
                              child:
                                  CircularProgressIndicator(strokeWidth: 2))
                          : const Text('توليد'),
                    ),
                  ),
          ),
        ],
      ),
    );
    label.dispose();
    uses.dispose();
    days.dispose();
    busy.dispose();
    result.dispose();
    if (done == true) await _load();
  }

  Future<void> _revokeKey(String id) async {
    try {
      await widget.api.ownerRevokeCourseKey(id);
      _toast('أُلغي المفتاح');
      await _load();
    } catch (e) {
      _toast(e is ApiException ? e.message : 'فشل الإلغاء');
    }
  }

  /// سحب تمكين مشترك — الأثر فوري: الطلب التالي من تثبيته يُرفض.
  Future<void> _revokeGrant(String installId, String courseId,
      String title, {String deviceId = ''}) async {
    final ok = await _confirm('سحب الوصول؟',
        'سيفقد هذا الجهاز الوصول إلى «$title» فوراً، حتى لو كان الفيديو '
        'محمّلاً عنده. يمكنك منحه مفتاحاً جديداً لاحقاً.');
    if (ok != true) return;
    try {
      await widget.api.ownerRevokeCourseGrant(installId, courseId,
          deviceId: deviceId);
      _toast('سُحب الوصول');
      await _load();
    } catch (e) {
      _toast(e is ApiException ? e.message : 'فشل السحب');
    }
  }

  Future<bool?> _confirm(String title, String body) => showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(XTheme.rLg)),
          title: Text(title,
              style:
                  const TextStyle(fontSize: 16.5, fontWeight: FontWeight.w900)),
          content: Text(body,
              style: TextStyle(
                  fontSize: 13, color: XTheme.textDim, height: 1.6)),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: Text('إلغاء', style: TextStyle(color: XTheme.textDim)),
            ),
            TextButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('تأكيد',
                  style: TextStyle(
                      color: XTheme.danger, fontWeight: FontWeight.w800)),
            ),
          ],
        ),
      );

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return Center(child: CircularProgressIndicator(color: XTheme.accent));
    }
    return Column(children: [
      TabBar(
        controller: _tabs,
        labelColor: XTheme.accent,
        unselectedLabelColor: XTheme.textDim,
        indicatorColor: XTheme.accent,
        labelStyle: const TextStyle(fontWeight: FontWeight.w800, fontSize: 12.5),
        tabs: const [
          Tab(text: 'الدورات'),
          Tab(text: 'المفاتيح'),
          Tab(text: 'المشتركون'),
        ],
      ),
      if (_msg != null)
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 8),
          child: Text(_msg!,
              style: TextStyle(fontSize: 12.5, color: XTheme.textDim)),
        ),
      Expanded(
        child: TabBarView(
          controller: _tabs,
          children: [_coursesView(), _keysView(), _subsView()],
        ),
      ),
    ]);
  }

  Widget _coursesView() {
    return Stack(children: [
      if (_courses.isEmpty)
        Center(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Icon(Icons.play_lesson_outlined,
                size: 46, color: XTheme.textDim),
            const SizedBox(height: 12),
            const Text('لا دورات بعد',
                style: TextStyle(fontSize: 14.5, fontWeight: FontWeight.w800)),
            const SizedBox(height: 6),
            Text('أنشئ دورة ثم أضف فيديوهاتها وولّد مفاتيح',
                style: TextStyle(fontSize: 12, color: XTheme.textDim)),
          ]),
        )
      else
        RefreshIndicator(
          onRefresh: _load,
          color: XTheme.accent,
          child: ListView(
            padding: const EdgeInsets.fromLTRB(12, 12, 12, 90),
            children: [
              for (final c in _courses) _courseTile(Map<String, dynamic>.from(c as Map)),
            ],
          ),
        ),
      Positioned(
        bottom: 16,
        left: 16,
        right: 16,
        child: FilledButton.icon(
          onPressed: () => _editCourse(),
          icon: const Icon(Icons.add, size: 19),
          label: const Text('دورة جديدة',
              style: TextStyle(fontWeight: FontWeight.w800)),
        ),
      ),
    ]);
  }

  Widget _courseTile(Map<String, dynamic> c) {
    final id = '${c['id']}';
    final title = '${c['title']}';
    final locked = c['locked'] == true;
    final published = c['published'] == true;
    final videos = (c['videos'] as List?) ?? const [];
    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      elevation: 0,
      color: XTheme.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(XTheme.rLg),
        side: BorderSide(color: XTheme.textDim.withOpacity(.15)),
      ),
      child: ExpansionTile(
        shape: const Border(),
        collapsedShape: const Border(),
        // غلاف الدورة متاح من هنا مباشرة، لا من داخل نافذة التعديل وحدها:
        // تغيير الصورة إجراء متكرّر لا يستحق فتح نموذج كامل من أجله.
        leading: _CourseCoverButton(
          api: widget.api,
          courseId: id,
          hasCover: '${c['coverUrl'] ?? ''}'.isNotEmpty,
          coverUrl: '${c['coverUrl'] ?? ''}',
          onUploaded: _load,
          onToast: _toast,
        ),
        title: Text(title,
            style:
                const TextStyle(fontSize: 14.5, fontWeight: FontWeight.w900)),
        subtitle: Padding(
          padding: const EdgeInsets.only(top: 4),
          child: Wrap(spacing: 6, runSpacing: 4, children: [
            _tag('${videos.length} فيديو', XTheme.textDim),
            _tag(locked ? 'يحتاج مفتاحاً' : 'مجانية',
                locked ? XTheme.gold : XTheme.ok),
            _tag('${c['subscriberCount'] ?? 0} مشترك', XTheme.cyan),
            _tag('${c['activeKeyCount'] ?? 0} مفتاح نشط', XTheme.accent),
            if (!published) _tag('مخفية', XTheme.danger),
          ]),
        ),
        childrenPadding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
        children: [
          for (final v in videos)
            ListTile(
              dense: true,
              contentPadding: EdgeInsets.zero,
              leading: Container(
                width: 48,
                height: 32,
                decoration: BoxDecoration(
                  color: XTheme.surface2,
                  borderRadius: BorderRadius.circular(6),
                ),
                clipBehavior: Clip.antiAlias,
                child: '${v['thumbUrl'] ?? ''}'.isEmpty
                    ? Icon(
                        '${v['mode']}' == 'free'
                            ? Icons.play_circle_outline
                            : Icons.lock_outline,
                        size: 18,
                        color: '${v['mode']}' == 'free'
                            ? XTheme.ok
                            : XTheme.gold,
                      )
                    : SignedImage(
                        api: widget.api,
                        path: '${v['thumbUrl']}',
                        fit: BoxFit.cover,
                        errorBuilder: () => Icon(
                            Icons.image_not_supported_outlined,
                            size: 16, color: XTheme.textDim),
                      ),
              ),
              title: Text('${v['title']}',
                  style: const TextStyle(
                      fontSize: 13, fontWeight: FontWeight.w700)),
              trailing: Row(mainAxisSize: MainAxisSize.min, children: [
                // المصغّرة: زر مستقل حتى يبدّل المالك الصورة وحدها بلا إعادة
                // رفع المقطع. اللون الأخضر يعني أن صورة موجودة فعلاً، فيعرف
                // أي درس ما زال بلا صورة بلمحة.
                IconButton(
                  tooltip: '${v['thumbUrl'] ?? ''}'.isEmpty
                      ? 'إضافة صورة مصغّرة'
                      : 'تغيير الصورة المصغّرة',
                  icon: Icon(Icons.image_outlined,
                      size: 19,
                      color: '${v['thumbUrl'] ?? ''}'.isEmpty
                          ? XTheme.textDim
                          : XTheme.ok),
                  onPressed: () async {
                    final img = await _pickImageB64();
                    if (img == null) return;
                    try {
                      await widget.api.ownerUploadCourseThumb(
                          '${v['id']}', img.b64, img.mime);
                      _toast('حُفظت الصورة المصغّرة');
                      await _load();
                    } catch (e) {
                      _toast(e is ApiException ? e.message : 'فشل رفع الصورة');
                    }
                  },
                ),
                // تعديل القفل بلا إعادة رفع: الرفع كان الوسيلة الوحيدة
                // لتغيير حالة الفيديو، فيضيع الرابط وتُستهلك الحصة.
                IconButton(
                  tooltip: 'تعديل الفيديو',
                  icon: const Icon(Icons.edit_outlined,
                      size: 19, color: XTheme.accent),
                  onPressed: () => _editVideo(courseId: id, video: v),
                ),
                IconButton(
                  tooltip: 'حذف الفيديو',
                  icon: const Icon(Icons.delete_outline,
                      size: 19, color: XTheme.danger),
                  onPressed: () async {
                    final ok = await _confirm('حذف الفيديو؟',
                        'سيُحذف «${v['title']}» من الدورة.');
                    if (ok != true) return;
                    try {
                      await widget.api.ownerDeleteVideo('${v['id']}');
                      await _load();
                    } catch (e) {
                      _toast(e is ApiException ? e.message : 'فشل الحذف');
                    }
                  },
                ),
              ]),
            ),
          const Divider(height: 16),
          Wrap(spacing: 8, runSpacing: 8, children: [
            OutlinedButton.icon(
              onPressed: () => _addVideo(id),
              icon: const Icon(Icons.video_call_outlined, size: 17),
              label: const Text('فيديو'),
            ),
            FilledButton.icon(
              onPressed: () => _genKey(id, title),
              icon: const Icon(Icons.key, size: 17),
              label: const Text('توليد مفتاح'),
            ),
            OutlinedButton.icon(
              onPressed: () => _editCourse(c),
              icon: const Icon(Icons.edit_outlined, size: 17),
              label: const Text('تعديل'),
            ),
            OutlinedButton.icon(
              onPressed: () => _deleteCourse(id, title),
              icon: const Icon(Icons.delete_outline,
                  size: 17, color: XTheme.danger),
              label: const Text('حذف',
                  style: TextStyle(color: XTheme.danger)),
              style: OutlinedButton.styleFrom(
                side: BorderSide(color: XTheme.danger.withOpacity(.4)),
              ),
            ),
          ]),
        ],
      ),
    );
  }

  Widget _keysView() {
    if (_keys.isEmpty) {
      return Center(
        child: Text('لا مفاتيح بعد — ولّد مفتاحاً من تبويب الدورات',
            style: TextStyle(fontSize: 12.5, color: XTheme.textDim)),
      );
    }
    return RefreshIndicator(
      onRefresh: _load,
      color: XTheme.accent,
      child: ListView.separated(
        padding: const EdgeInsets.fromLTRB(12, 12, 12, 24),
        itemCount: _keys.length,
        separatorBuilder: (_, __) => const SizedBox(height: 8),
        itemBuilder: (_, i) {
          final k = Map<String, dynamic>.from(_keys[i] as Map);
          final revoked = k['revoked'] == true;
          final used = (k['usedCount'] as num?)?.toInt() ?? 0;
          final max = (k['maxUses'] as num?)?.toInt() ?? 1;
          return Card(
            elevation: 0,
            color: XTheme.surface,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(XTheme.rMd),
              side: BorderSide(
                  color: revoked
                      ? XTheme.danger.withOpacity(.35)
                      : XTheme.textDim.withOpacity(.15)),
            ),
            child: ListTile(
              title: Text('${k['courseTitle']}',
                  style: const TextStyle(
                      fontSize: 13.5, fontWeight: FontWeight.w800)),
              subtitle: Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Wrap(spacing: 6, runSpacing: 4, children: [
                  _tag('$used / $max استخدام',
                      used >= max ? XTheme.danger : XTheme.ok),
                  if ('${k['label']}'.isNotEmpty)
                    _tag('${k['label']}', XTheme.textDim),
                  if (revoked) _tag('ملغى', XTheme.danger),
                ]),
              ),
              trailing: revoked
                  ? const Icon(Icons.block, color: XTheme.danger, size: 20)
                  : IconButton(
                      tooltip: 'إلغاء المفتاح',
                      icon: const Icon(Icons.block, size: 20),
                      onPressed: () => _revokeKey('${k['id']}'),
                    ),
            ),
          );
        },
      ),
    );
  }

  Widget _subsView() {
    if (_subs.isEmpty) {
      return Center(
        child: Text('لا مشتركين بعد',
            style: TextStyle(fontSize: 12.5, color: XTheme.textDim)),
      );
    }
    return RefreshIndicator(
      onRefresh: _load,
      color: XTheme.accent,
      child: ListView.separated(
        padding: const EdgeInsets.fromLTRB(12, 12, 12, 24),
        itemCount: _subs.length,
        separatorBuilder: (_, __) => const SizedBox(height: 8),
        itemBuilder: (_, i) {
          final s = Map<String, dynamic>.from(_subs[i] as Map);
          return Card(
            elevation: 0,
            color: XTheme.surface,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(XTheme.rMd),
              side: BorderSide(color: XTheme.textDim.withOpacity(.15)),
            ),
            child: ListTile(
              leading: const Icon(Icons.person_outline,
                  color: XTheme.cyan, size: 22),
              title: Text('${s['courseTitle']}',
                  style: const TextStyle(
                      fontSize: 13.5, fontWeight: FontWeight.w800)),
              subtitle: Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text('الجهاز: ${s['shortId'] ?? ''}',
                    style: TextStyle(
                        fontSize: 11.5, color: XTheme.textDim)),
              ),
              trailing: TextButton.icon(
                onPressed: () => _revokeGrant(
                    '${s['installId'] ?? ''}', '${s['courseId']}',
                    '${s['courseTitle']}',
                    deviceId: '${s['deviceId'] ?? ''}'),
                icon: const Icon(Icons.remove_circle_outline, size: 16),
                label: const Text('سحب'),
                style: TextButton.styleFrom(foregroundColor: XTheme.danger),
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _tag(String t, Color color) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
        decoration: BoxDecoration(
          color: color.withOpacity(.12),
          borderRadius: BorderRadius.circular(20),
        ),
        child: Text(t,
            style: TextStyle(
                fontSize: 10, fontWeight: FontWeight.w800, color: color)),
      );
}


/// زر غلاف الدورة: يعرض الصورة الحالية ويستبدلها بضغطة.
///
/// صورة الغلاف تمرّ من الخادم موقّعة كبقية الصور، فلا يُكشف مفتاح R2 الخام.
class _CourseCoverButton extends StatelessWidget {
  const _CourseCoverButton({
    required this.api,
    required this.courseId,
    required this.hasCover,
    required this.coverUrl,
    required this.onUploaded,
    required this.onToast,
  });

  final Api api;
  final String courseId;
  final bool hasCover;
  final String coverUrl;
  final Future<void> Function() onUploaded;
  final void Function(String) onToast;

  @override
  Widget build(BuildContext context) {
    final thumb = Container(
      width: 46,
      height: 46,
      decoration: BoxDecoration(
        color: XTheme.surface2,
        borderRadius: BorderRadius.circular(10),
      ),
      clipBehavior: Clip.antiAlias,
      child: hasCover
          ? SignedImage(
              api: api,
              path: coverUrl,
              fit: BoxFit.cover,
              errorBuilder: () => Icon(
                  Icons.image_not_supported_outlined,
                  size: 16, color: XTheme.textDim),
            )
          : Icon(Icons.image_outlined, size: 18, color: XTheme.textDim),
    );
    return Tooltip(
      message: hasCover ? 'تغيير صورة الدورة' : 'إضافة صورة للدورة',
      child: InkWell(
        borderRadius: BorderRadius.circular(10),
        onTap: () async {
          final picker = ImagePicker();
          final picked = await picker.pickImage(
              source: ImageSource.gallery, maxWidth: 1280, imageQuality: 88);
          if (picked == null) return;
          try {
            final bytes = await picked.readAsBytes();
            await api.ownerUploadCourseCover(
                courseId, base64Encode(bytes), 'image/jpeg');
            onToast('حُفظ غلاف الدورة');
            await onUploaded();
          } catch (e) {
            onToast(e is ApiException ? e.message : 'فشل رفع الغلاف');
          }
        },
        child: thumb,
      ),
    );
  }
}
