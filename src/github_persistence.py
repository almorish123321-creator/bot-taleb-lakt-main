"""
GitHub Gist Persistence — حفظ كل الإعدادات والجلسات في Gist مشفر

الميزة:
- حفظ جلسات الحسابات (StringSession) في Gist خاص على GitHub
- حفظ كل الإعدادات (الكلمات المفتاحية، الفلاتر، المشرفين، القوالب، القروبات...)
- التشفير باستخدام Fernet (AES-128-CBC + HMAC)
- الاستعادة التلقائية عند بدء التشغيل
- بقاء البيانات بعد كل deploy/تحديث/إعادة تشغيل
- المستخدمون لا يتأثرون بأي تحديث للبوت — كل بياناتهم تبقى

ما يُحفظ (كل الإعدادات):
- SESSIONS: جلسات الحسابات
- ACCOUNT_OWNERS: مالكو الحسابات
- ADMIN_GROUP_ID: قروب الأدمن لاستقبال نسخة من كل الرسائل
- FORWARD_GROUPS: قروبات التوجيه المعتمدة
- USER_GROUPS: قروبات التوجيه لكل مستخدم
- KEYWORDS: الكلمات المفتاحية
- DEFAULT_KEYWORDS: الكلمات المفتاحية الافتراضية
- IGNORE_USERS: قائمة التجاهل
- ADMINS: المشرفون المضافون
- ADMIN_ROLES: رتب المشرفين
- FILTERS: إعدادات الفلترة
- DETECT_LINKS: كشف الروابط
- DM_REPLY_TEMPLATES: قوالب الرد الخاص
- GROUP_REPLY_TEMPLATES: قوالب الرد في القروب
- AUTO_REPLY_SETTINGS: الردود التلقائية
- BANNED_ADS: الكلمات الإعلانية المحظورة
- SUSPICIOUS_WORDS: الكلمات المشبوهة
- DUPLICATE_DETECTION: كشف التكرار
- AUTO_DELETE_HOURS: ساعات الحذف التلقائي
- LOG_RETENTION_DAYS: مدة الاحتفاظ بسجل الدردشة
- TARGET_GROUPS: قائمة القروبات للعرض
- BANNED_USERS: المستخدمون المحظورون

Env vars المطلوبة:
- GITHUB_TOKEN: توكن GitHub PAT مع صلاحية gist
- GIST_ID: معرف الـ Gist
- ENCRYPTION_KEY: مفتاح Fernet
"""

import os
import json
import base64
import logging
import time
import requests
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GIST_ID = os.getenv("GIST_ID", "")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")

_fernet = None
if ENCRYPTION_KEY:
    try:
        _fernet = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)
    except Exception as e:
        logger.error(f"❌ ENCRYPTION_KEY غير صالح: {e}")

GIST_FILENAME = "sessions.enc"

# كل المفاتيح التي تُحفظ في Gist (الإعدادات كاملة)
PERSISTED_KEYS = [
    # الجلسات والإعدادات المتعلقة بها
    "SESSIONS",
    "ACCOUNT_OWNERS",
    "ADMIN_GROUP_ID",
    "FORWARD_GROUPS",
    "USER_GROUPS",
    # الكلمات والقوائم
    "KEYWORDS",
    "DEFAULT_KEYWORDS",
    "IGNORE_USERS",
    "BANNED_ADS",
    "SUSPICIOUS_WORDS",
    # المشرفون والصلاحيات
    "ADMINS",
    "ADMIN_ROLES",
    "BANNED_USERS",
    # الفلاتر
    "FILTERS",
    "DETECT_LINKS",
    "DUPLICATE_DETECTION",
    # قوالب الرد
    "DM_REPLY_TEMPLATES",
    "GROUP_REPLY_TEMPLATES",
    "AUTO_REPLY_SETTINGS",
    # الإعدادات العامة
    "AUTO_DELETE_HOURS",
    "LOG_RETENTION_DAYS",
    "TARGET_GROUPS",
]


def is_configured():
    """فحص إذا كانت الميزة مضبوطة بالكامل"""
    return bool(GITHUB_TOKEN and GIST_ID and _fernet)


def _encrypt(data: dict) -> str:
    """تشفير dict وتحويله لـ base64 string"""
    raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
    encrypted = _fernet.encrypt(raw)
    return base64.b64encode(encrypted).decode("ascii")


def _decrypt(content_b64: str) -> dict:
    """فك تشفير base64 string واستعادته كـ dict"""
    encrypted = base64.b64decode(content_b64)
    raw = _fernet.decrypt(encrypted)
    return json.loads(raw.decode("utf-8"))


def _gist_api(method, endpoint, payload=None):
    """استدعاء GitHub API للـ Gists"""
    url = f"https://api.github.com/gists/{endpoint}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }
    return requests.request(method, url, headers=headers, json=payload, timeout=30)


def save_all_settings(config: dict):
    """حفظ كل الإعدادات في Gist (مشفر)

    Args:
        config: dict كامل بالإعدادات (من load_json_config)
    Returns:
        True إذا نجح، False إذا فشل
    """
    if not is_configured():
        logger.warning("⚠️ GitHub persistence غير مضبوط — لن تُحفظ الإعدادات في Gist")
        return False

    try:
        # تجهيز البيانات — نسخ فقط المفاتيح المعروفة
        data = {}
        for key in PERSISTED_KEYS:
            if key in config:
                data[key] = config[key]
        data["saved_at"] = int(time.time())
        data["version"] = 3

        encrypted_content = _encrypt(data)

        # جلب الـ gist الحالي
        get_resp = _gist_api("GET", GIST_ID)
        if get_resp.status_code != 200:
            logger.error(f"❌ فشل جلب الـ Gist: {get_resp.status_code} {get_resp.text[:200]}")
            return False

        # تحديث الـ gist
        update_payload = {
            "description": "Bot full settings encrypted storage (auto-managed)",
            "files": {
                GIST_FILENAME: {
                    "content": encrypted_content
                }
            }
        }
        update_resp = _gist_api("PATCH", GIST_ID, update_payload)
        if update_resp.status_code == 200:
            sessions_count = len(data.get("SESSIONS", {}))
            keywords_count = len(data.get("KEYWORDS", []))
            forward_count = len(data.get("FORWARD_GROUPS", []))
            admins_count = len(data.get("ADMINS", []))
            logger.info(
                f"💾 تم حفظ كل الإعدادات في GitHub Gist (مشفر): "
                f"{sessions_count} جلسة، {keywords_count} كلمة مفتاحية، "
                f"{forward_count} قروب توجيه، {admins_count} مشرف"
            )
            return True
        else:
            logger.error(f"❌ فشل تحديث الـ Gist: {update_resp.status_code} {update_resp.text[:200]}")
            return False
    except Exception as e:
        logger.error(f"❌ خطأ في حفظ الإعدادات في Gist: {e}")
        return False


def load_all_settings():
    """تحميل كل الإعدادات من Gist

    Returns:
        dict بكل الإعدادات أو None إذا فشل
    """
    if not is_configured():
        logger.warning("⚠️ GitHub persistence غير مضبوط — لا يمكن تحميل الإعدادات من Gist")
        return None

    try:
        resp = _gist_api("GET", GIST_ID)
        if resp.status_code != 200:
            logger.error(f"❌ فشل جلب الـ Gist: {resp.status_code}")
            return None

        gist_data = resp.json()
        files = gist_data.get("files", {})
        file_info = files.get(GIST_FILENAME)
        if not file_info:
            logger.warning(f"⚠️ الملف {GIST_FILENAME} غير موجود في الـ Gist")
            return None

        content_b64 = file_info.get("content", "").strip()
        if not content_b64:
            logger.info("ℹ️ الـ Gist فارغ — لا توجد بيانات محفوظة")
            return {}

        data = _decrypt(content_b64)
        # ضمان وجود كل المفاتيح (للتوافق مع النسخ القديمة)
        result = {}
        for key in PERSISTED_KEYS:
            result[key] = data.get(key, _default_for_key(key))
        logger.info(
            f"📂 تم تحميل الإعدادات من GitHub Gist: "
            f"{len(result.get('SESSIONS', {}))} جلسة، "
            f"{len(result.get('KEYWORDS', []))} كلمة مفتاحية، "
            f"{len(result.get('FORWARD_GROUPS', []))} قروب توجيه، "
            f"{len(result.get('ADMINS', []))} مشرف"
        )
        return result
    except InvalidToken:
        logger.error("❌ فشل فك التشفير — ENCRYPTION_KEY غير صحيح أو البيانات تالفة")
        return None
    except Exception as e:
        logger.error(f"❌ خطأ في تحميل الإعدادات من Gist: {e}")
        return None


def _default_for_key(key):
    """القيمة الافتراضية لكل مفتاح"""
    defaults = {
        "SESSIONS": {},
        "ACCOUNT_OWNERS": {},
        "ADMIN_GROUP_ID": 0,
        "FORWARD_GROUPS": [],
        "USER_GROUPS": {},
        "KEYWORDS": [],
        "DEFAULT_KEYWORDS": [],
        "IGNORE_USERS": [],
        "BANNED_ADS": [],
        "SUSPICIOUS_WORDS": [],
        "ADMINS": [],
        "ADMIN_ROLES": {},
        "BANNED_USERS": [],
        "FILTERS": {},
        "DETECT_LINKS": True,
        "DUPLICATE_DETECTION": True,
        "DM_REPLY_TEMPLATES": [],
        "GROUP_REPLY_TEMPLATES": [],
        "AUTO_REPLY_SETTINGS": {},
        "AUTO_DELETE_HOURS": 0,
        "LOG_RETENTION_DAYS": 3,
        "TARGET_GROUPS": [],
    }
    return defaults.get(key, None)


# دالات التوافق مع النسخة السابقة
def save_sessions(sessions_dict, account_owners=None, admin_group_id=None, forward_groups=None):
    """حفظ الجلسات والإعدادات المتعلقة بها في Gist (للتوافق مع النسخة السابقة)

    ملاحظة: ينصح باستخدام save_all_settings(config) بدلاً من هذه الدالة
    """
    if not is_configured():
        return False
    try:
        # تحميل الإعدادات الموجودة من Gist
        existing = load_all_settings() or {}
        # تحديث بالقيم الجديدة
        if sessions_dict is not None:
            existing["SESSIONS"] = sessions_dict
        if account_owners is not None:
            existing["ACCOUNT_OWNERS"] = account_owners
        if admin_group_id is not None:
            existing["ADMIN_GROUP_ID"] = admin_group_id
        if forward_groups is not None:
            existing["FORWARD_GROUPS"] = forward_groups
        return save_all_settings(existing)
    except Exception as e:
        logger.error(f"❌ خطأ في save_sessions: {e}")
        return False


def load_sessions():
    """تحميل الجلسات (للتوافق مع النسخة السابقة)"""
    data = load_all_settings()
    if data is None:
        return None
    return {
        "SESSIONS": data.get("SESSIONS", {}),
        "ACCOUNT_OWNERS": data.get("ACCOUNT_OWNERS", {}),
        "ADMIN_GROUP_ID": data.get("ADMIN_GROUP_ID", 0),
        "FORWARD_GROUPS": data.get("FORWARD_GROUPS", []),
    }


def get_status():
    """حالة الميزة للتشخيص"""
    return {
        "configured": is_configured(),
        "gist_id": GIST_ID[:8] + "..." if GIST_ID else None,
        "github_token_set": bool(GITHUB_TOKEN),
        "encryption_key_set": bool(_fernet),
        "persisted_keys": PERSISTED_KEYS,
        "persisted_keys_count": len(PERSISTED_KEYS),
    }


if __name__ == "__main__":
    print("Status:", get_status())
    if is_configured():
        # اختبار حفظ كل الإعدادات
        test_config = {
            "SESSIONS": {"phone_test": "test_session"},
            "ACCOUNT_OWNERS": {"phone_test": 12345},
            "ADMIN_GROUP_ID": -1001234567890,
            "FORWARD_GROUPS": [{"id": -1001234567890, "title": "Test"}],
            "USER_GROUPS": {"12345": [-1001234567890]},
            "KEYWORDS": ["يسوي", "يحل", "احد"],
            "DEFAULT_KEYWORDS": ["يسوي"],
            "IGNORE_USERS": [],
            "ADMINS": [7853478744],
            "ADMIN_ROLES": {},
            "BANNED_USERS": [],
            "FILTERS": {"max_length": 0, "block_links": False},
            "DETECT_LINKS": True,
            "DUPLICATE_DETECTION": True,
            "DM_REPLY_TEMPLATES": [],
            "GROUP_REPLY_TEMPLATES": [],
            "AUTO_REPLY_SETTINGS": {},
            "AUTO_DELETE_HOURS": 0,
            "LOG_RETENTION_DAYS": 3,
            "TARGET_GROUPS": [],
        }
        ok = save_all_settings(test_config)
        print(f"Save: {ok}")
        loaded = load_all_settings()
        print(f"Load: {loaded}")
