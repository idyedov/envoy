from __future__ import absolute_import, division, print_function, unicode_literals
import os
basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY', '\xd9\x90\x02.\xd7\xc6F\xc4\xaa\x1d\x0b\xeal\xc0D\xf1F\x12\x03\xf4\x90wq6')
    SSL_DISABLE = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    GOOGLE_CONSUMER_KEY = os.environ.get('GOOGLE_CONSUMER_KEY')
    GOOGLE_CONSUMER_SECRET = os.environ.get('GOOGLE_CONSUMER_SECRET')

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True


class ProductionConfig(Config):
    pass

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
}
