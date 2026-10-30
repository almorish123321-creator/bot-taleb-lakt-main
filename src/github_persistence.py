"""
GitHub Gist Persistence — حفظ الجلسات مشفرة في Gist خاص

الميزة:
- حفظ جلسات الحسابات (StringSession) في Gist خاص على GitHub
- التشفير باستخدام Fernet (AES-128-CBC + HMAC)
- الاستعادة التلقائية عند بدء التشغيل
- بقاء الجلسات بعد كل deploy/تحديث/إعادة تشغيل

Env vars المطلوبة:
- GITHUB_TOKEN: توكن GitHub PAT مع صلاحية gist
- GIST_ID: معرف الـ Gist (رقم/حروف)
- ENCRYPTION_KEY: مفتاح Fernet (يتم توليده مرة واحدة)
"""

import os
import json
import base64
import logging
import time
import requests
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

# قراءة الإعدادات من env vars
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GIST_ID = os.getenv("GIST_ID", "")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")

# تهيئة Fernet cipher (لو المفتاح موجود)
_fernet = None
if ENCRYPTION_KEY:
    try:
        _fernet = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)
    except Exception as e:
        logger.error(f"❌ ENCRYPTION_KEY غير صالح: {e}")

# ملف Gist الذي يحوي الجلسات
GIST_FILENAME = "sessions.enc"


def is_configured():
    """فحص إذا كانت الميزة مضبوطة بالكامل"""
    return bool(GITHUB_TOKEN and GIST_ID and _fernet)


def _encrypt(data: dict) -> str:
    """تشفير dict وتحويله لـ base64 string قابل للتخزين في Gist"""
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
    resp = requests.request(method, url, headers=headers, json=payload, timeout=30)
    return resp


def save_sessions(sessions_dict, account_owners=None):
    """حفظ جلسات الحسابات في Gist (مشفر)

    Args:
        sessions_dict: {phone: string_session}
        account_owners: {phone: user_id} (اختياري)
    Returns:
        True إذا نجح، False إذا فشل
    """
    if not is_configured():
        logger.warning("⚠️ GitHub persistence غير مضبوط — لن تُحفظ الجلسات في Gist")
        return False

    try:
        # تجهيز البيانات
        data = {
            "SESSIONS": sessions_dict,
            "ACCOUNT_OWNERS": account_owners or {},
            "saved_at": int(time.time()),
            "version": 1,
        }
        encrypted_content = _encrypt(data)

        # جلب الـ gist الحالي للحصول على sha (مطلوب للتحديث)
        get_resp = _gist_api("GET", GIST_ID)
        if get_resp.status_code != 200:
            logger.error(f"❌ فشل جلب الـ Gist: {get_resp.status_code} {get_resp.text[:200]}")
            return False

        # تحديث الـ gist
        update_payload = {
            "description": "Bot sessions encrypted storage (auto-managed)",
            "files": {
                GIST_FILENAME: {
                    "content": encrypted_content
                }
            }
        }
        update_resp = _gist_api("PATCH", GIST_ID, update_payload)
        if update_resp.status_code == 200:
            logger.info(f"💾 تم حفظ {len(sessions_dict)} جلسة في GitHub Gist (مشفر)")
            return True
        else:
            logger.error(f"❌ فشل تحديث الـ Gist: {update_resp.status_code} {update_resp.text[:200]}")
            return False
    except Exception as e:
        logger.error(f"❌ خطأ في حفظ الجلسات في Gist: {e}")
        return False


def load_sessions():
    """تحميل الجلسات المحفوظة من Gist

    Returns:
        dict: {"SESSIONS": {phone: string}, "ACCOUNT_OWNERS": {phone: user_id}}
        أو None إذا فشل
    """
    if not is_configured():
        logger.warning("⚠️ GitHub persistence غير مضبوط — لا يمكن تحميل الجلسات من Gist")
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
            logger.info("ℹ️ الـ Gist فارغ — لا توجد جلسات محفوظة")
            return {"SESSIONS": {}, "ACCOUNT_OWNERS": {}}

        data = _decrypt(content_b64)
        sessions = data.get("SESSIONS", {})
        owners = data.get("ACCOUNT_OWNERS", {})
        logger.info(f"📂 تم تحميل {len(sessions)} جلسة من GitHub Gist (مشفر)")
        return {"SESSIONS": sessions, "ACCOUNT_OWNERS": owners}
    except InvalidToken:
        logger.error("❌ فشل فك التشفير — ENCRYPTION_KEY غير صحيح أو البيانات تالفة")
        return None
    except Exception as e:
        logger.error(f"❌ خطأ في تحميل الجلسات من Gist: {e}")
        return None


def get_status():
    """حالة الميزة للتشخيص"""
    return {
        "configured": is_configured(),
        "gist_id": GIST_ID[:8] + "..." if GIST_ID else None,
        "github_token_set": bool(GITHUB_TOKEN),
        "encryption_key_set": bool(_fernet),
    }


if __name__ == "__main__":
    # اختبار سريع
    print("Status:", get_status())
    if is_configured():
        # حفظ بيانات تجريبية
        test_data = {"phone_test": "test_session_string_123"}
        ok = save_sessions(test_data, {"phone_test": 12345})
        print(f"Save: {ok}")
        # تحميل
        loaded = load_sessions()
        print(f"Load: {loaded}")
