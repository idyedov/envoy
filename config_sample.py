""" SAMPLE CONFIG """
from __future__ import unicode_literals

SECRET_KEY = "\xd9\x90\x02.\xd7\xc6F\xc4\xaa\x1d\x0b\xeal\xc0D\xf1F\x12\x03\xf4\x90wq6"
GOOGLE_CONSUMER_KEY = "KEY"
GOOGLE_CONSUMER_SECRET = "SECRET"
GOOGLE_DOMAIN = None
DEBUG = False
TESTING = False
APPS = [
  # name is the url route, needs to be url-safe
  {"name": "jenkins", "url": "http://localhost:8080"},
  {"name": "munin", "url": "http://localhost/munin"}
]
# set to one of the above to be displayed as the root app
DEFAULT_APP = None
