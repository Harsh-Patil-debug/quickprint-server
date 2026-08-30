"""
Django settings for QuickPrint backend.
Mirrors khelomore-server/server/server/settings.py structure and security posture exactly.
"""

from pathlib import Path
import os
from dotenv import load_dotenv
from django.core.exceptions import ImproperlyConfigured

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent


def _require_env(name):
    """
    SECURITY: fail closed instead of silently falling back to a hardcoded default secret.
    A hardcoded fallback here is visible to anyone with repo access and would grant
    authentication/session-forging capability in any deployment that forgets to set it.
    """
    value = os.getenv(name)
    if not value:
        raise ImproperlyConfigured(f"Required environment variable '{name}' is not set.")
    return value


SECRET_KEY = _require_env('DJANGO_SECRET_KEY')

# SECURITY: default to DEBUG=False. Verbose Django error pages leak secrets, environment
# details, and stack traces to whoever triggers a 500 — never let that be the silent
# default. Set DEBUG=True explicitly in .env for local development.
DEBUG = os.getenv('DEBUG', 'False') == 'True'

_allowed_hosts_env = os.getenv('ALLOWED_HOSTS', '')
if _allowed_hosts_env:
    ALLOWED_HOSTS = [h.strip() for h in _allowed_hosts_env.split(',') if h.strip()]
elif DEBUG:
    ALLOWED_HOSTS = ['*']
else:
    raise ImproperlyConfigured("ALLOWED_HOSTS must be set (comma-separated) via env when DEBUG=False.")

NGROK_DOMAIN = os.getenv('NGROK_DOMAIN', '')


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'quickprint_project.main',
    'rest_framework',
    'corsheaders',
]

REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '60/minute',
        'user': '300/minute',
        # Tighter than the defaults above — applied via ScopedRateThrottle to
        # login/register/verify-otp-style credential-guessing surface specifically.
        'auth': '20/minute',
        # Applied to the file-upload endpoint (real work: Cloudinary upload + PDF
        # parsing per request) — same reasoning as khelomore-server's 'geo' scope for
        # its outbound-network-call endpoint.
        'upload': '20/minute',
    }
}

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'quickprint_project.main.middleware.OriginValidationMiddleware',
]

# CORS
# SECURITY: same reasoning as khelomore-server — set CORS_ALLOWED_ORIGINS (comma-separated
# real frontend domains, e.g. https://quickprint.app,https://shop.quickprint.app) once
# known; falls back to wildcard only while DEBUG=True.
_cors_origins_env = os.getenv('CORS_ALLOWED_ORIGINS', '')
CORS_ALLOWED_ORIGINS = []
CORS_ALLOW_ALL_ORIGINS = False
if _cors_origins_env:
    CORS_ALLOWED_ORIGINS = [o.strip() for o in _cors_origins_env.split(',') if o.strip()]
elif DEBUG:
    CORS_ALLOW_ALL_ORIGINS = True
else:
    raise ImproperlyConfigured("CORS_ALLOWED_ORIGINS must be set (comma-separated) via env when DEBUG=False.")
CORS_ALLOW_CREDENTIALS = True

from corsheaders.defaults import default_headers

CORS_ALLOW_HEADERS = list(default_headers) + [
    "ngrok-skip-browser-warning",
]

CORS_ALLOW_METHODS = [
    "DELETE",
    "GET",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
]

CORS_EXPOSE_HEADERS = ["Content-Type", "X-CSRFToken"]

APPEND_SLASH = False

ROOT_URLCONF = 'server.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'server.wsgi.application'


# Database — SQLite for Django internals (sessions, admin)
# MongoDB is used directly via pymongo in Handlers/db_connection.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]


# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Kolkata'
USE_I18N = True
USE_L10N = True
USE_TZ = True


# Static files
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

# App URLs
BACKEND_URL = os.getenv('BACKEND_URL', 'http://localhost:8000')
CUSTOMER_WEB_URL = os.getenv('CUSTOMER_WEB_URL', 'http://localhost:8080')
SHOP_DASHBOARD_URL = os.getenv('SHOP_DASHBOARD_URL', 'http://localhost:8081')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET', '')

# Cashfree Keys — platform account. CASHFREE_ENV switches sandbox vs production for the
# whole payments module with one env var (mirrors khelomore-server).
CASHFREE_CLIENT_ID = os.getenv('CASHFREE_CLIENT_ID', '')
CASHFREE_CLIENT_SECRET = os.getenv('CASHFREE_CLIENT_SECRET', '')
CASHFREE_ENV = os.getenv('CASHFREE_ENV', 'sandbox')

# Cloudinary — document/file storage (raw resource uploads for print jobs)
CLOUDINARY_CLOUD_NAME = os.getenv('CLOUDINARY_CLOUD_NAME', '')
CLOUDINARY_API_KEY = os.getenv('CLOUDINARY_API_KEY', '')
CLOUDINARY_API_SECRET = os.getenv('CLOUDINARY_API_SECRET', '')

# Admin Security — used by super-admin-only endpoints (platform ops), same pattern as
# khelomore-server's ADMIN_TOKEN.
ADMIN_TOKEN = _require_env('ADMIN_TOKEN')

# Reused by OriginValidationMiddleware (quickprint_project/main/middleware.py) for
# CSRF-style protection on cookie-authenticated state-changing requests. Empty (i.e. not
# enforced) until CORS_ALLOWED_ORIGINS is explicitly configured. QuickPrint's web apps are
# Bearer-token-only for v1 (no auth cookies issued), so this middleware is a structural
# no-op today — kept in place so it activates automatically if cookie-based auth is ever
# added, exactly as it did for khelomore-server's admin panel.
ALLOWED_ORIGINS = CORS_ALLOWED_ORIGINS


# ── Security headers (skipped in DEBUG so local http:// dev keeps working) ─────────────────
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'

if not DEBUG:
    # Render (and every similar PaaS) terminates TLS at its own edge proxy and forwards
    # the request over plain HTTP internally. Without trusting X-Forwarded-Proto, Django
    # would "redirect" every already-HTTPS request to HTTPS again forever — see
    # khelomore-server/server/server/settings.py for the incident this guards against.
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
