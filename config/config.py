import os


class Config(object):
    DEBUG = False
    TESTING = False
    SECRET_KEY = b'\xb8YJ\xb1\xed\xfeK~\x94\xfb\x17>\xd9\x17\xe4\x95'

    DB_NAME = "production-db"
    DB_USERNAME = "admin"
    DB_PASSWORD = "example"

    IMAGE_UPLOADS = "static/images"

    SESSION_COOKIE_SECURE = True


class ProductionConfig(Config):
    pass


class DevelopmentConfig(Config):
    # Stripe Keys
    STRIPE_PUBLIC_KEY = ''
    STRIPE_SECRET_KEY = ''

    UPLOADED_PHOTOS_DEST = 'static/images'
    UPLOADS_DEFAULT_DEST = 'static/images'

    SQLALCHEMY_DATABASE_URI = ''
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    DEBUG = True
    SESSION_COOKIE_SECURE = False

    # Mail Configs

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = '587'
    MAIL_USE_TLS = True
    MAIL_SSL = False
    MAIL_DEBUG = True
    MAIL_USERNAME = ''
    MAIL_PASSWORD = ''
    MAIL_DEFAULT_SENDER = ''
    MAIL_MAX_EMAILS = None
    MAIL_SUPPRESS_SEND = False
    MAIL_ASCII_ATTACHMENTS = False

    REQUEST_URL = 'http://127.0.0.1:5000/'
