"""
Supabase Persistence — حفظ الجلسات والإعدادات في قاعدة بيانات Supabase

الميزة:
- حفظ جلسات الحسابات في جدول `sessions`
- حفظ كل الإعدادات في جدول `bot_settings` (JSONB)
- الاستعادة التلقائية عند بدء التشغيل
- بقاء البيانات بعد كل deploy/تحديث/إعادة تشغيل
- أسرع من GitHub Gist بكثير (فوري بدل كل 5 دقائق)

الجداول المطلوبة في Supabase:
- sessions (phone TEXT PK, session_string TEXT, owner_id BIGINT, updated_at TIMESTAMPTZ)
- bot_settings (key TEXT PK, value JSONB, updated_at TIMESTAMPTZ)

Env vars المطلوبة:
- SUPABASE_URL: https://xxxxx.supabase.co
- SUPABASE_SECRET_KEY: sb_secret_xxxxxxxxxxxxxxxxxxxx
"""

import os
import json
import logging
import time
from typing import Optional, Dict, Any, List
from supabase import create_client, Client

logger = logging.getLogger(__name__)

# قراءة الإعدادات من env vars
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SECRET_KEY = os.getenv("SUPABASE_SECRET_KEY", "").strip()

# إنشاء عميل Supabase (مرة واحدة)
_supabase: Optional[Client] = None
if SUPABASE_URL and SUPABASE_SECRET_KEY:
    try:
        _supabase = create_client(SUPABASE_URL, SUPABASE_SECRET_KEY)
        logger.info("🌐 Supabase client initialized successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize Supabase client: {e}")

# أسماء الجداول
SESSIONS_TABLE = "sessions"
SETTINGS_TABLE = "bot_settings"

# المفاتيح التي تُحفظ في Supabase (نفس مفاتيح Gist)
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
    "ADMIN_PERMISSIONS",
    "MAX_ACCOUNTS_PER_USER",
    # الفلاتر
    "FILTERS",
    "DETECT_LINKS",
    "DUPLICATE_DETECTION",
    # قوالب الرد
    "DM_REPLY_TEMPLATES",
    "GROUP_REPLY_TEMPLATES",
    "AUTO_REPLY_SETTINGS",
    # إعدادات المستخدمين
    "USER_KEYWORDS",
    "USER_DELETED_DEFAULTS",
    "USER_DM_TEMPLATES",
    "USER_GRP_TEMPLATES",
    # الإعدادات العامة
    "AUTO_DELETE_HOURS",
    "LOG_RETENTION_DAYS",
    "TARGET_GROUPS",
]


def is_configured() -> bool:
    """فحص إذا كانت الميزة مضبوطة بالكامل"""
    return bool(_supabase is not None)


def _default_for_key(key: str) -> Any:
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
        "ADMIN_PERMISSIONS": {},
        "MAX_ACCOUNTS_PER_USER": 3,
        "FILTERS": {},
        "DETECT_LINKS": True,
        "DUPLICATE_DETECTION": True,
        "DM_REPLY_TEMPLATES": [],
        "GROUP_REPLY_TEMPLATES": [],
        "AUTO_REPLY_SETTINGS": {},
        "USER_KEYWORDS": {},
        "USER_DELETED_DEFAULTS": {},
        "USER_DM_TEMPLATES": {},
        "USER_GRP_TEMPLATES": {},
        "AUTO_DELETE_HOURS": 0,
        "LOG_RETENTION_DAYS": 3,
        "TARGET_GROUPS": [],
    }
    return defaults.get(key, None)


# ============ حفظ/استعادة الجلسات ============

def save_session(phone: str, session_string: str, owner_id: Optional[int] = None) -> bool:
    """حفظ أو تحديث جلسة حساب في جدول sessions"""
    if not is_configured():
        return False
    try:
        data = {
            "phone": str(phone),
            "session_string": session_string,
        }
        if owner_id is not None:
            data["owner_id"] = int(owner_id)
        # upsert = insert أو update لو موجود
        _supabase.table(SESSIONS_TABLE).upsert(data, on_conflict="phone").execute()
        return True
    except Exception as e:
        logger.error(f"❌ فشل حفظ جلسة {phone} في Supabase: {e}")
        return False


def delete_session(phone: str) -> bool:
    """حذف جلسة من جدول sessions"""
    if not is_configured():
        return False
    try:
        _supabase.table(SESSIONS_TABLE).delete().eq("phone", str(phone)).execute()
        return True
    except Exception as e:
        logger.error(f"❌ فشل حذف جلسة {phone} من Supabase: {e}")
        return False


def load_all_sessions() -> Dict[str, Dict[str, Any]]:
    """تحميل كل الجلسات من جدول sessions

    Returns:
        dict: {
            "phone1": {"session_string": "...", "owner_id": 123},
            ...
        }
    """
    if not is_configured():
        return {}
    try:
        response = _supabase.table(SESSIONS_TABLE).select("phone, session_string, owner_id").execute()
        sessions = {}
        for row in response.data:
            sessions[row["phone"]] = {
                "session_string": row.get("session_string"),
                "owner_id": row.get("owner_id"),
            }
        return sessions
    except Exception as e:
        logger.error(f"❌ فشل تحميل الجلسات من Supabase: {e}")
        return {}


def get_session_owners() -> Dict[str, int]:
    """تحميل مالكي الحسابات فقط (phone → owner_id)"""
    sessions = load_all_sessions()
    return {phone: info.get("owner_id") for phone, info in sessions.items() if info.get("owner_id") is not None}


# ============ حفظ/استعادة الإعدادات ============

def save_setting(key: str, value: Any) -> bool:
    """حفظ أو تحديث إعداد واحد في جدول bot_settings"""
    if not is_configured():
        return False
    try:
        data = {
            "key": key,
            "value": json.loads(json.dumps(value, ensure_ascii=False, default=str)),
        }
        _supabase.table(SETTINGS_TABLE).upsert(data, on_conflict="key").execute()
        return True
    except Exception as e:
        logger.error(f"❌ فشل حفظ إعداد {key} في Supabase: {e}")
        return False


def load_setting(key: str, default: Any = None) -> Any:
    """تحميل إعداد واحد من جدول bot_settings"""
    if not is_configured():
        return default
    try:
        response = _supabase.table(SETTINGS_TABLE).select("value").eq("key", key).execute()
        if response.data:
            return response.data[0].get("value", default)
        return default
    except Exception as e:
        logger.error(f"❌ فشل تحميل إعداد {key} من Supabase: {e}")
        return default


def load_all_settings() -> Dict[str, Any]:
    """تحميل كل الإعدادات من جدول bot_settings

    Returns:
        dict: {key1: value1, key2: value2, ...}
    """
    if not is_configured():
        return {}
    try:
        response = _supabase.table(SETTINGS_TABLE).select("key, value").execute()
        settings = {}
        for row in response.data:
            settings[row["key"]] = row.get("value")
        return settings
    except Exception as e:
        logger.error(f"❌ فشل تحميل الإعدادات من Supabase: {e}")
        return {}


def save_all_settings(config: Dict[str, Any]) -> bool:
    """حفظ كل الإعدادات في جدول bot_settings (دفعة واحدة)

    Args:
        config: dict كامل بالإعدادات
    Returns:
        True لو نجح، False لو فشل
    """
    if not is_configured():
        return False
    try:
        # تجهيز كل الصفوف للحفظ
        rows = []
        for key in PERSISTED_KEYS:
            if key in config:
                rows.append({
                    "key": key,
                    "value": json.loads(json.dumps(config[key], ensure_ascii=False, default=str)),
                })
        # حفظ كل صف على حدة (upsert)
        # Supabase يدعم bulk upsert
        if rows:
            _supabase.table(SETTINGS_TABLE).upsert(rows, on_conflict="key").execute()
        return True
    except Exception as e:
        logger.error(f"❌ فشل حفظ كل الإعدادات في Supabase: {e}")
        return False


def save_full_config(config: Dict[str, Any]) -> bool:
    """حفظ كامل: الجلسات في جدول sessions + الإعدادات في bot_settings

    Args:
        config: dict كامل بالإعدادات (يحتوي على SESSIONS و ACCOUNT_OWNERS)
    Returns:
        True لو نجح
    """
    if not is_configured():
        return False
    success = True
    # 1) حفظ الجلسات في جدول sessions
    sessions = config.get("SESSIONS", {})
    owners = config.get("ACCOUNT_OWNERS", {})
    for phone, session_string in sessions.items():
        owner_id = owners.get(str(phone)) or owners.get(phone)
        if not save_session(phone, session_string, owner_id):
            success = False
    # 2) حفظ باقي الإعدادات في bot_settings (ما عدا SESSIONS و ACCOUNT_OWNERS)
    other_settings = {k: v for k, v in config.items() if k not in ("SESSIONS", "ACCOUNT_OWNERS")}
    if not save_all_settings(other_settings):
        success = False
    # 3) حفظ ACCOUNT_OWNERS كإعداد في bot_settings
    if owners:
        if not save_setting("ACCOUNT_OWNERS", owners):
            success = False
    return success


def load_full_config() -> Dict[str, Any]:
    """تحميل كامل: الجلسات + الإعدادات

    Returns:
        dict: كل الإعدادات + SESSIONS + ACCOUNT_OWNERS
    """
    if not is_configured():
        return {}
    result = {}
    # 1) تحميل الإعدادات من bot_settings
    settings = load_all_settings()
    result.update(settings)
    # 2) تحميل الجلسات من sessions
    sessions_data = load_all_sessions()
    result["SESSIONS"] = {phone: info["session_string"] for phone, info in sessions_data.items()}
    # 3) استعادة ACCOUNT_OWNERS
    owners_from_settings = settings.get("ACCOUNT_OWNERS", {})
    owners_from_sessions = {phone: info.get("owner_id") for phone, info in sessions_data.items() if info.get("owner_id") is not None}
    # دمج (sessions له الأولوية)
    merged_owners = {**owners_from_settings, **owners_from_sessions}
    result["ACCOUNT_OWNERS"] = merged_owners
    return result


def get_status() -> Dict[str, Any]:
    """حالة الميزة للتشخيص"""
    return {
        "configured": is_configured(),
        "supabase_url": SUPABASE_URL[:40] + "..." if SUPABASE_URL else None,
        "secret_key_set": bool(SUPABASE_SECRET_KEY),
        "persisted_keys_count": len(PERSISTED_KEYS),
        "backend": "supabase" if is_configured() else None,
    }


# ============ ترحيل من GitHub Gist ============

def migrate_from_gist(gist_data: Dict[str, Any]) -> bool:
    """ترحيل البيانات من GitHub Gist إلى Supabase

    Args:
        gist_data: dict بكل البيانات من github_persistence.load_all_settings()
    Returns:
        True لو نجح
    """
    if not is_configured():
        return False
    try:
        # حفظ الجلسات
        sessions = gist_data.get("SESSIONS", {})
        owners = gist_data.get("ACCOUNT_OWNERS", {})
        migrated = 0
        for phone, session_string in sessions.items():
            owner_id = owners.get(str(phone)) or owners.get(phone)
            if save_session(phone, session_string, owner_id):
                migrated += 1
        logger.info(f"🌐 تم ترحيل {migrated} جلسة من Gist إلى Supabase")
        # حفظ باقي الإعدادات
        other_settings = {k: v for k, v in gist_data.items() if k not in ("SESSIONS", "saved_at", "version")}
        if save_all_settings(other_settings):
            logger.info("🌐 تم ترحيل كل الإعدادات من Gist إلى Supabase")
        return True
    except Exception as e:
        logger.error(f"❌ فشل الترحيل من Gist إلى Supabase: {e}")
        return False


if __name__ == "__main__":
    # اختبار سريع
    print("Status:", get_status())
    if is_configured():
        # حفظ بيانات تجريبية
        ok = save_setting("_test_key", {"hello": "world", "numbers": [1, 2, 3]})
        print(f"Save setting: {ok}")
        val = load_setting("_test_key")
        print(f"Load setting: {val}")
        # حفظ جلسة تجريبية
        ok2 = save_session("+1234567890", "test_session_string_123", owner_id=7853478744)
        print(f"Save session: {ok2}")
        sessions = load_all_sessions()
        print(f"Sessions: {sessions}")
        # تنظيف
        delete_session("+1234567890")
        from supabase import create_client as cc
        # حذف الإعداد التجريبي
        _supabase.table(SETTINGS_TABLE).delete().eq("key", "_test_key").execute()
        print("✅ Cleanup done")
