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

USE_OIDC = True
USE_IDENTITY_PROVIDERS = True

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
                    'uid_field': 'sub',
                },
            }
        ],
    }
}
