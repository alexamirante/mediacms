import os

FRONTEND_HOST = os.getenv('FRONTEND_HOST', 'http://localhost')
PORTAL_NAME = os.getenv('PORTAL_NAME', 'MediaCMS')
SECRET_KEY = os.getenv('SECRET_KEY', 'ma!s3^b-cw!f#7s6s0m3*jx77a@riw(7701**(r=ww%w!2+yk2')
REDIS_LOCATION = os.getenv('REDIS_LOCATION', 'redis://redis:6379/1')

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv('POSTGRES_NAME', 'mediacms'),
        "HOST": os.getenv('POSTGRES_HOST', 'db'),
        "PORT": os.getenv('POSTGRES_PORT', '5432'),
        "USER": os.getenv('POSTGRES_USER', 'mediacms'),
        "PASSWORD": os.getenv('POSTGRES_PASSWORD', 'mediacms'),
        "OPTIONS": {'pool': True},
    }
}

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": REDIS_LOCATION,
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        },
    }
}

# CELERY STUFF
BROKER_URL = REDIS_LOCATION
CELERY_RESULT_BACKEND = BROKER_URL

MP4HLS_COMMAND = "/home/mediacms.io/bento4/bin/mp4hls"

DEBUG = os.getenv('DEBUG', 'False') == 'True'
GLOBAL_LOGIN_REQUIRED = True
CAN_ADD_MEDIA = "advancedUser"

USE_OIDC = True
USE_IDENTITY_PROVIDERS = True
OIDC_REDIRECT_URI = os.getenv('OIDC_REDIRECT_URI', '')
OIDC_AUTH_PARAMS = {'redirect_uri': OIDC_REDIRECT_URI} if OIDC_REDIRECT_URI else {}
OIDC_CLAIMS_MAPPING = {
    'uid': 'sub',
    'name': 'name',
    'email': 'email',
    'first_name': 'given_name',
    'last_name': 'family_name',
    'groups': 'groups',
    'role': 'roles',
    'picture': 'picture',
}

# Map OIDC role candidates (bare or "role:group") to MediaCMS global roles.
# Values: user | advancedUser | editor | manager | admin
OIDC_GLOBAL_ROLE_MAPPINGS = {
    # 'secr:secretariat': 'admin',
    # 'chair': 'editor',
    # 'wikiadmin': 'editor',
}

# Map OIDC role candidates to RBAC membership roles inside a group.
# Values: member | contributor | manager
OIDC_GROUP_ROLE_MAPPINGS = {
    # 'chair': 'manager',
    # 'reviewer': 'contributor',
    # 'delegate': 'member',
}

SOCIALACCOUNT_PROVIDERS = {
    'openid_connect': {
        'OAUTH_PKCE_ENABLED': True,
        'APPS': [
            {
                'provider_id': 'ietf-dt',
                'name': 'IETF Datatracker',
                'client_id': os.getenv('OIDC_CLIENT_ID', ''),
                'secret': os.getenv('OIDC_CLIENT_SECRET', ''),
                'settings': {
                    'server_url': 'https://dt-main.dev.ietf.org/api/openid',
                    'fetch_userinfo': True,
                    'oauth_pkce_enabled': True,
                    'token_auth_method': 'client_secret_basic',
                    'auth_params': OIDC_AUTH_PARAMS,
                    'uid_field': 'sub',
                    'scope': ['openid', 'profile', 'email', 'roles'],
                },
            }
        ],
    }
}
