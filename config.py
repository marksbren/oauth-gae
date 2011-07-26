import os

from google.appengine.ext import webapp
from google.appengine.ext.webapp import util
from google.appengine.api.urlfetch import DownloadError 
from google.appengine.api import images
from django.utils import simplejson
from google.appengine.datastore import entity_pb
from google.appengine.api import memcache

import oauth2
import uuid
import logging
import pprint
import re
import sys
import StringIO
import os
import cgi
from math import (radians, sin, cos, atan2, degrees)
from datetime import (datetime, date, timedelta)
import urllib
import urllib2

TOKEN_COOKIE = 'plainsq_token'
TOKEN_PREFIX = 'token_plainsq_'

COORD_PREFIX = 'coord_plainsq_'

USERID_PREFIX = 'userid_plainsq_'

AUTH_URL = 'https://foursquare.com/oauth2/authenticate'
ACCESS_URL = 'https://foursquare.com/oauth2/access_token'
API_URL = 'https://api.foursquare.com/v2'

DEFAULT_LAT = '39.7'
DEFAULT_LON = '-75.6'
DEBUG_COOKIE = 'plainsq_debug'

METERS_PER_MILE = 1609.344

USER_AGENT = 'RandomWalk:0.0.1 20110721'

if os.environ.get('SERVER_SOFTWARE','').startswith('Devel'):
	# In development environment, use local callback.
	# Also need to use a different consumer because Foursquare
	# checks the callback URL.
	CALLBACK_URL = 'http://localhost:8081/oauth'
	CLIENT_ID = '313XKCMSSWSWHW2PRZX231LBRIGB4OFCESREW5T1E2Z5MBPR'
	CLIENT_SECRET = 'P4AFGZNDXIU5MCBWMOUTZLHCHYWDC5RFOEYP3I2EZAP3SNIO'
else:
	# Production environment.
	CALLBACK_URL = 'https://shaftsms.appspot.com/oauth'
	CLIENT_ID = 'PMYCZBZWZ2F0VOH11YIKE4RKVHA54LEDREBRT3XELLNIAFOF'
	CLIENT_SECRET = 'N4QVKFREBTT3PTZTJXKNH0NZ1YI2SZ4X13YCWDD5GDTI5TMD'