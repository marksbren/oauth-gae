from config import *
from models import *

def escape(s):
	return cgi.escape(s, quote = True)

def pprint_to_str(obj):
	"""
	Pretty print to a string buffer then return the string.
	"""
	sb = StringIO.StringIO()
	pp = pprint.pprint(obj, sb, 4)
	return sb.getvalue()

def debug_json(self, jsn):
	"""
	Pretty-print a JSON response.
	"""
	if get_debug(self):
				self.response.out.write('<pre>%s</pre>' % escape(pprint_to_str(jsn)))

def set_debug(self, debug):
	"""
	Set the debug option cookie.
	"""
	self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; expires=Fri, 31-Dec-2020 23:59:59 GMT'
			% (DEBUG_COOKIE, debug))

def get_debug(self):
	"""
	Get the debug setting from cookie. If cookie is not found,
	assume we are not in debug mode.
	"""
	debug = self.request.cookies.get(DEBUG_COOKIE)
	if debug is None:
				return 0
	return int(debug)

def no_cache(self):
	"""
	Turn off web caching so that the browser will refetch the page.
	Also set the user-agent header.
	"""
	self.response.headers.add_header('Cache-Control', 'no-cache') 
	self.response.headers.add_header('User-Agent', USER_AGENT) 


def set_userid(self, userid):
	"""
	Cache the userid.
	"""
	uuid = self.request.cookies.get(TOKEN_COOKIE)
	if uuid is not None:
				memcache.set(USERID_PREFIX + uuid, userid)


def get_userid(self):
	"""
	Get the cached userid, if available.
	"""
	uuid = self.request.cookies.get(TOKEN_COOKIE)
	if uuid is not None:
				return memcache.get(USERID_PREFIX + uuid)


def query_coords(self, uuid = None):
	"""
	Run a GQL query to get the coordinates, if available.
	"""
	if uuid is None:
				uuid = self.request.cookies.get(TOKEN_COOKIE)
	if uuid is not None:
				return CoordsTable.gql('WHERE uuid=:1 LIMIT 1', uuid).get()

def set_coords(self, lat, lon):
	"""
	Store the coordinates in our table.
	"""
	result = query_coords(self)
	if result is None:
				uuid = self.request.cookies.get(TOKEN_COOKIE)
				if uuid is not None:
					coord_str = "%s,%s" % (lat, lon)
					CoordsTable(uuid = uuid, coords = coord_str).put()
					# Update memcache.
					memcache.set(COORD_PREFIX + uuid, coord_str)
	else:
				# Update existing record.
				result.coords = "%s,%s" % (lat, lon)
				db.put(result)
				# Update memcache.
				memcache.set(COORD_PREFIX + result.uuid, result.coords)

def get_coord_str(self):
	"""
	Given the token cookie, get coordinates either from
	memcache or datastore.
	"""

	# Try to get coordinates from memcache first.
	uuid = self.request.cookies.get(TOKEN_COOKIE)
	if uuid is not None:
		coord_key = COORD_PREFIX + uuid

		coord_str = memcache.get(coord_key)
		if coord_str is not None:
			return coord_str

		# If not in memcache, try the datastore.
		result = query_coords(self, uuid)
		if result is not None:
			coord_str = result.coords
			memcache.set(coord_key, coord_str)
			return coord_str

	return None

def coords(self):
	"""
	Get user's coordinates from coords table. If not found in table,
	use default coordinates.
	"""
	lat = None
	lon = None

	coord_str = get_coord_str(self)

	if coord_str is not None:
		try:
			(lat, lon) = coord_str.split(',')
		except ValueError:
			pass

	if lat is None or lon is None:
		lat = DEFAULT_LAT
		lon = DEFAULT_LON
		set_coords(self, lat, lon)

	return (lat, lon)

def newclient():
	"""
	Create a new oauth2 client.
	"""
	return oauth2.Client(
			client_id = CLIENT_ID,
			client_secret = CLIENT_SECRET,
			callback_url = CALLBACK_URL,
			auth_url = AUTH_URL,
			access_url = ACCESS_URL,
			api_url = API_URL)

def getclient(self):
	"""
	Check if login cookie is available. If it is, use the access token from
	the database. Otherwise, do the OAuth handshake.
	"""
	uuid = self.request.cookies.get(TOKEN_COOKIE)
	access_token = None

	if uuid is not None:
		uuid_key = TOKEN_PREFIX + uuid

		# Try to get access token from memcache first.
		access_token = memcache.get(uuid_key)
		if access_token is None:
		
			# Retrieve the access token using the login cookie.
			result = AccessToken.gql("WHERE uuid = :1 LIMIT 1",
					uuid_key).get()
			# If the query fails for whatever reason, the user will just
			# have to log in again. Not such a big deal.
			if result is not None:
				access_token = result.token
				memcache.set(uuid_key, access_token)

	client = newclient()

	if access_token is not None:
		# We have an access token. Use it.
		client.setAccessToken(access_token)
		return client

	self.response.out.write('Not logged in.')
	self.redirect('/login')

def htmlbegin(self, title):
	self.response.out.write(
"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>PlainSq - %s</title>

<meta name="HandheldFriendly" content="true" />
<meta name="viewport" content="width=device-width, height=device-height, user-scalable=yes" />

<link rel="stylesheet" href="/screen.css" media="all" type="text/css">
<link rel="stylesheet" href="/handheld.css" media="handheld, only screen and (max-device-width:480px)" type="text/css">

</head>

<body>
<p><a class="button" href="/"><b>PlainSq</b></a> - %s
""" % (title, title))

def htmlend(self, noabout=False, nologout=False):
	self.response.out.write("""
<hr>
<a class="button" href="/">Home</a>%s%s
</body>
</html>
""" % (
	'' if noabout else '<span class="linksep"> | </span><a class="button" href="/about">About</a>',
	'' if nologout else '<span class="linksep"> | </span><a class="button" href="/logout">Log out</a>'))

def conv_a_coord(coord, nsew):
	coord = float(coord)

	d = nsew[0]
	if coord < 0:
		d = nsew[1]
		coord = -coord

	return '%s%02d %06.3f' % (d, int(coord), 60 * (coord - int(coord)))

def convcoords(lat, lon):
	"""
	Convert coordinates from decimal degrees to dd mm.mmm.
	Returns the result as a string.
	"""
	return conv_a_coord(lat, 'NS') + ' ' + conv_a_coord(lon, 'EW')

def call4sq(self, client, method, path, params = None):
	"""
	Call the Foursquare API. Handle errors.
	Returns None if there was an error. Otherwise, returns the parsed JSON.
	"""
	try:
		if method == 'post':
			result = client.post(path, params)
		else:
			result = client.get(path, params)

		jsn = simplejson.loads(result)

		meta = jsn.get('meta')
		if meta is not None:
			errorType = meta.get('errorType', '')
			errorDetail = meta.get('errorDetail', '')

			if errorType == 'deprecated':
				self.response.out.write('<p><span class="error">Deprecated: %s</span>' % errorDetail)
				return jsn

			if errorType != '' or errorDetail != '':
				errorpage(self, '%s : %s' % (errorType, errorDetail))
				return

		return jsn

	except DownloadError:
		errorpage(self,
				"Can't connect to Foursquare. #SadMayor Refresh to retry.")
		return

	except urllib2.HTTPError, e:
		jsn = simplejson.loads(e.read())
		meta = jsn.get('meta', {})
		errormsg = meta.get('errorDetail', 'Unknown error')
		errorpage(self, 
				'Error %d from Foursquare API call to %s:<br>%s' % (e.code, e.geturl(), errormsg))
		return


def errorpage(self, msg, errcode=503):
	"""
	Used for DownloadError exceptions and other errors. Generates an error
	page.
	"""
	self.error(errcode)

	htmlbegin(self, "Error")
	self.response.out.write('<p><span class="error">Error: %s</span>' % msg)
	htmlend(self)

def userheader(self, client, lat, lon, badges=0, mayor=0):
	""" 
	Display the logged-in user's icon, name, and position.
	"""
	jsn = call4sq(self, client, 'get', '/users/self')
	if jsn is None:
		return

	response = jsn.get('response')
	if response is None:
		logging.error('Missing response from /users/self:')
		logging.error(jsn)
		return jsn

	user = response.get('user')
	if user is None:
		logging.error('Missing user from /users/self:')
		logging.error(jsn)
		return jsn

	firstname = user.get('firstName', '')
	photo = user.get('photo', '')

	venueName = ''
	checkins = user.get('checkins')
	if checkins is not None:
		items = checkins.get('items')
		if items is not None and len(items) > 0:
			venue = items[0].get('venue')
			if venue is not None:
				venueName = venue.get('name', '')

	self.response.out.write(
			'<p><img src="%s" style="float:left"> %s @ %s<br>Loc: %s'
			'<br style="clear:both">' 
			% (photo, escape(firstname), escape(venueName),
				convcoords(lat, lon)))

	return user
	
def venue_cmds(venue, checkin_long=False):
	"""
	Show checkin/moveto links in venue header.
	"""
	s = ''
	# s = '<a class="vbutton" href="/checkin?vid=%s">checkin</a>' % venue['id']
	if checkin_long:
		s += ' <a class="vbutton" href="/checkin_long?%s">checkin with options</a>' % \
				escape(urllib.urlencode( { 
					'vid' : venue['id'], 
					'vname' : venue['name'].encode('utf-8')
					} ))

	location = venue.get('location')
	if location is not None:
		lat = location.get('lat')
		lng = location.get('lng')
		if lat is not None and lng is not None:
			s += ' <a class="vbutton" href="/coords?%s">move to</a>' % \
					escape(urllib.urlencode( {
						'geolat' : lat,
						'geolong' : lng,
						} ))

	# Link to venue page on Foursquare regular website.
	s += ' <a class="vbutton" href="http://foursquare.com/venue/%s">web</a>' % venue['id']

	s += """<form style="margin:0; padding:0;" action="/checkin" method="post">
<input type="hidden" name="vid" value="%s">
<input class="formbutton" type="submit" value="checkin">
</form>""" % venue['id']

	return '<span class="buttonbox">%s</span>' % s

def addr_fmt(venue):
	"""
	Format the address block of a venue.
	"""
	location = venue.get('location', {})
	contact = venue.get('contact', {})
	return addr_fmt_2(location, contact)

def addr_fmt_2(location, contact):
	"""
	Format an address block from location and contact records.
	"""
	s = ''

	if location is not None:
		addr = location.get('address', '')
		if addr != '':
			s += escape(addr) + '<br>'

		cross = location.get('crossStreet', '')
		if cross != '':
			s += '(%s)<br>' % escape(cross)

		city = location.get('city', '')
		state = location.get('state', '')
		zip = location.get('postalCode', '')
		country = location.get('country', '')
		if city != '' or state != '' or zip != '' or country != '':
			s += '%s, %s %s %s<br>' % (
					escape(city), escape(state), escape(zip), escape(country))

	if contact is not None:
		phone = contact.get('phone', '')
		if len(phone) > 6:
			s += '(%s)%s-%s<br>' % (phone[0:3], phone[3:6], phone[6:])

		twitter = contact.get('twitter', '')

		# Discard invalid characters.
		twitter = re.sub(r'[^a-zA-Z0-9_]', '', twitter)

		if len(twitter) > 0:
			s += '<a href="http://mobile.twitter.com/%s">@%s</a><br>' % (
					urllib.quote(twitter), escape(twitter))

	return s

def category_fmt(cat):
	path = ' / '.join(cat['parents'] + [ cat['name'] ])
	return """
<p><img src="%s" style="float:left">%s
<br style="clear:both">
""" % (cat['icon'], path)

def google_map(lat, lon):
	"""
	Static Google Map.
	"""
	return """
<p><img width="150" height="150" alt="[Google Map]"
src="http://maps.google.com/maps/api/staticmap?%s">
""" % escape(urllib.urlencode( {
	'size' : '150x150', 
	'format' : 'gif',
	'sensor' : 'false',
	'zoom' : '14',
	'markers' : 'size:mid|color:blue|%s,%s' % (lat, lon),
	} ))

def fuzzy_delta(delta):
	"""
	Returns a user-friendly version of timedelta.
	"""
	if delta.days < 0:
		return 'in the future?'
	elif delta.days > 1:
		return '%d days ago' % delta.days
	elif delta.days == 1:
		return '1 day ago'
	else:
		hours = int(delta.seconds / 60 / 60)
		if hours > 1:
			return '%d hours ago' % hours
		elif hours == 1:
			return '1 hour ago'
		else:
			minutes = int(delta.seconds / 60)
			if minutes > 1:
				return '%d minutes ago' % minutes
			elif minutes == 1:
				return '1 minute ago'
			else:
				if delta.seconds > 1:
					return '%d seconds ago' % delta.seconds
				elif delta.seconds == 1:
					return '1 second ago'
				else:
					return 'now'

def name_fmt(user):
	if user is None:
		return ''
	return escape('%s %s' % (
			user.get('firstName', ''),
			user.get('lastName', ''))
			)

def venue_checkin_fmt(checkin, dnow):
	"""
	Format the info about a user checked in at this venue.
	"""
	s = ''
	s += '<p><img src="%s" style="float:left">%s from %s' % (
			checkin['user']['photo'],
			name_fmt(checkin['user']),
			escape(checkin['user'].get('homeCity', '')))

	shout = checkin.get('shout')
	if shout is not None:
		s += '<br>"%s"' % escape(shout)

	d1 = datetime.fromtimestamp(checkin['createdAt'])
	s += '<br>%s' % fuzzy_delta(dnow - d1)

	s += '<br style="clear:both">'
	return s

def vinfo_fmt(venue):
	"""
	Format info on a venue.
	"""
	s = ''

	s += '<p>%s %s<br>%s' % (
			escape(venue['name']),
			venue_cmds(venue, checkin_long=True),
			addr_fmt(venue))

	location = venue.get('location', {})
	if location is not None:
		lat = location.get('lat')
		lng = location.get('lng')
		if lat is not None and lng is not None:
			# Add static Google Map to the page.
			s += google_map(lat, lng)

	cats = venue.get('categories', [])
	s += ''.join([category_fmt(c) for c in cats])

	tags = venue.get('tags', [])
	if len(tags) > 0:
		s += '<p>Tags: %s' % escape(', '.join(tags))

	stats = venue.get('stats')
	if stats is not None:
		s += """
<p>Checkins: %s <br>Users: %s
""" % (stats['checkinsCount'], stats['usersCount'])

	beenhere = venue.get('beenHere')
	if beenhere is not None:
		s += """
<br>Your checkins: %s
""" % beenhere['count']

	herenow = venue.get('hereNow')
	if herenow is not None:
		s += """
<br>Here now: %s
""" % herenow['count']

	mayor = venue.get('mayor')
	if mayor is not None:
		user = mayor.get('user')

	if user is None:
		s += '<p>No mayor'
	else:
		s += """
<p><img src="%s" style="float:left">%s (%sx) 
from %s is the mayor<br style="clear:both"> 
""" % (user['photo'], 
		name_fmt(user),
		mayor['count'], 
		escape(user.get('homeCity', '')))

	if herenow is not None:
		if herenow['count'] > 0:
			s += '<p><b>Checked in here:</b>'
		hngroups = herenow.get('groups', [])
		dnow = datetime.utcnow()
		for g in hngroups:
			items = g.get('items', [])
			s += ''.join(
					[venue_checkin_fmt(c, dnow) for c in items])

	s += tips_fmt(venue.get('tips', []))
	s += specials_fmt(venue.get('specials', []))
	s += specials_fmt(venue.get('specialsNearby', []), nearby=True)

	photos = venue.get('photos')
	if photos is None:
		count = 0
	else:
		count = photos.get('count', 0)

	if count == 0:
		s += '<p>-- No photos --'
	else:
		for group in photos['groups']:
			s += '<p>-- %s: %d --' % (group['name'], group['count'])
			s += ''.join([photo_fmt(p, dnow, venue_id = venue['id']) 
				for p in group['items']])

	s += """
<p>
<form style="margin:0; padding:0;" enctype="multipart/form-data" action="/addphoto" method="post">
<input type="file" name="photo"><br>
<input type="hidden" value="%s" name="venid">
<input type="submit" value="Add JPEG photo"><br>
</form>
""" % venue['id']

	return s

def get_prim_category(cats):
	if cats is not None:
		for c in cats:
			if c.get('primary', False):
				return c
	return None

def special_fmt(special):
	"""
	Format a venue special.
	"""
	s = ''
	venue = special.get('venue', {})

	pcat = get_prim_category(venue.get('categories'))
	if pcat is not None:
		s += category_fmt(pcat)

	s += '<p>%s (%s): %s / %s' % (
			escape(venue.get('name', '')), special['type'],
			escape(special.get('message', '')),
			escape(special.get('description', '')),
			)
	return s


def specials_fmt(specials, nearby=False):
	"""
	Format venue specials.
	"""
	return '' if len(specials) == 0 else '<p><b>Specials%s:</b>' % (
			' nearby' if nearby else ''
			) + '<ul class="seplist">%s</ul>' % ''.join(
					['<li>%s</li>' % special_fmt(x) for x in specials])

def tip_fmt(tip):
	"""
	Format a tip on the venue page.
	"""
	return """
<p><img src="%s" style="float:left">%s from %s says: 
%s (Posted: %s)<br style="clear:both">
""" % (tip['user']['photo'],
		name_fmt(tip['user']),
		escape(tip['user'].get('homeCity', '')),
		escape(tip['text']),
		datetime.fromtimestamp(tip['createdAt']).ctime())

def tips_fmt(tips):
	"""
	Format a list of tips on the venue page.
	"""
	s = ''
	if tips['count'] > 0:
		s += '<p><b>Tips:</b>'
	for grp in tips['groups']:
		s += ''.join([tip_fmt(t) for t in grp['items']])
	return s
	

def pluralize(count, what):
	if count == 0:
		s = 'no %ss' % what
	elif count == 1:
		s = '1 %s' % what
	else:
		s = '%d %ss' % (count, what)
	return s

def comments_cmd(checkin):
	comments = checkin.get('comments')
	if comments is None:
		count = 0
	else:
		count = comments.get('count', 0)

	cstr = pluralize(count, 'comment')

	photos = checkin.get('photos')
	if photos is None:
		count = 0
	else:
		count = photos.get('count', 0)

	pstr = pluralize(count, 'photo')

	return '<span class="buttonbox"><a class="vbutton" href="/comments?chkid=%s">%s, %s</a></span>' % (
			checkin['id'], cstr, pstr)

def history_checkin_fmt(checkin, dnow):
	"""
	Format an item from the check-in history.
	"""
	s = ''

	venue = checkin.get('venue')
	if venue is not None:
		id = venue.get('id')
		# Orphaned venues will be missing the id field.
		if id is None:
			s += '<b>%s</b><br>' % escape(venue['name'])
		else:
			s += '<a class="button" href="/venue?vid=%s"><b>%s</b></a> %s<br>%s' % (
					id, escape(venue['name']), venue_cmds(venue),
					addr_fmt(venue)
					)
	else:
		location = checkin.get('location')
		if location is not None:
			s += '<p>%s (venueless)<br>' % location.get('name', '')

	shout = checkin.get('shout')
	if shout is not None:
		s += '"%s"<br>' % escape(shout)

	s += '%s<br>' % comments_cmd(checkin)

	d1 = datetime.fromtimestamp(checkin['createdAt'])
	s += fuzzy_delta(dnow - d1)

	return s


def mayor_venue_fmt(venue):
	return '<li><a class="button" href="/venue?vid=%s"><b>%s</b></a> %s<br>%s</li>' % (
			venue['id'], escape(venue['name']), venue_cmds(venue),
			addr_fmt(venue))




COMPASS_DIRS = [ 'S', 'SW', 'W', 'NW', 'N', 'NE', 'E', 'SE', 'S' ]

def bearing(lat, lon, vlat, vlon):
	"""
	Compute compass direction from (lat, lon) to (vlat, vlon)
	"""
	dlon = radians(float(vlon) - float(lon))
	lat1 = radians(float(lat))
	lat2 = radians(float(vlat))

	y = sin(dlon) * cos(lat2)
	x = cos(lat1) * sin(lat2) - sin(lat1) * cos(lat2) * cos(dlon)
	brng = degrees(atan2(y, x))

	return COMPASS_DIRS[int((brng + 180 + 22.5) / 45)]

def friend_checkin_fmt(checkin, lat, lon, dnow):
	"""
	Format checkin record from one friend.
	"""
	s = '<p>'

	venue = checkin.get('venue')
	user = checkin.get('user')

	user_shown = False

	if venue is not None:
		s += '<a class="button" href="/venue?vid=%s"><b>%s</b> @ %s</a><br>' % (
				venue.get('id'),
				name_fmt(user),
				venue.get('name', ''),
				)
		user_shown = True
	else:
		location = checkin.get('location', {})
		name = location.get('name')
		if name is not None:
			s += '<b>%s</b> @ %s<br>' % (name_fmt(user), name)
			user_shown = True

	shout = checkin.get('shout')
	if shout is not None:
		if not user_shown:
			s += '<b>' + name_fmt(user) + '</b> '
		s += '"%s"<br>' % escape(shout)

	s += '%s<br>' % comments_cmd(checkin)

	dist = checkin.get('distance')
	if dist is not None:
		dist = float(dist) / METERS_PER_MILE

	if venue is not None:
		s += addr_fmt(venue)
		location = venue.get('location', {})
	else:
		location = checkin.get('location', {})

	geolat = location.get('lat')
	geolong = location.get('lng')

	if geolat is None or geolong is None:
		compass = ''
	else:
		compass = ' ' + bearing(lat, lon, geolat, geolong)

	if dist is not None:
		s += '(%.1f mi%s)<br>' % (dist, compass)

	d1 = datetime.fromtimestamp(checkin['createdAt'])
	s += fuzzy_delta(dnow - d1)

	return s


def venue_fmt(venue, lat, lon):
	"""
	Format a venue in the venue search page.
	"""
	s = ''

	s += '<a class="button" href="/venue?vid=%s"><b>%s</b></a> %s<br>%s' % (
			venue['id'], escape(venue['name']), 
			venue_cmds(venue), addr_fmt(venue))

	location = venue.get('location')
	if location is not None:
		# Show distance and bearing from current coordinates.
		dist = location.get('distance')
		if dist is not None:
			dist = float(dist) / METERS_PER_MILE
			vlat = location.get('lat')
			vlng = location.get('lng')
			compass = ''
			if vlat is not None and vlng is not None:
				compass = bearing(lat, lon, vlat, vlng)
			s += '(%.1f mi %s)<br>' % (dist, compass)

	return s

def venues_fmt(jsn, lat, lon):
	"""
	Format a list of venues in the venue search page.
	"""

	groups = jsn.get('groups')
	if groups is None:
		venues = jsn.get('venues', [])
	else:
		# Venues may be split across groups so collect them all in one list.
		venues = []
		for group in groups:
			venues.extend(group['items'])

	venues = remove_dup_vids(venues)

	# Sort venues ascending by distance. If distance field is missing,
	# use a very large value.
	venues.sort(key = lambda v: v['location'].get('distance', '1000000'))

	return """
<ul class="vlist">
%s
</ul>
""" % ''.join(['<li>%s</li>' % venue_fmt(v, lat, lon) for v in venues])

def remove_dup_vids(venues):
	"""
	Return a new list of venues with all duplicate entries removed.
	"""
	vids = []
	newvenues = []
	for v in venues:
		id = v['id']
		if id not in vids:
			vids.append(id)
			newvenues.append(v)
	return newvenues
	
def deg_min(st):
	deg = st[:2]
	min = st[2:]
	if min == '':
		min = '0'
	if len(min) > 2:
		min = min[:2] + '.' + min[2:]
	return (deg, min)

def parse_coord(coordstr):
	"""
	Parse user-entered coordinates.
	These coordinates are entered as digits only. The string is split into
	two halves. The first half fills in dd mm.mmm in the latitude and 
	the second half fills in dd mm.mmm in the longitude.
	"""
	mid = int((len(coordstr) + 1) / 2)
	latstr = coordstr[:mid]
	lonstr = coordstr[mid:]

	(d, m) = deg_min(latstr)
	lat = "%.6f" % (int(d) + float(m) / 60)

	(d, m) = deg_min(lonstr)
	lon = "%.6f" % -(int(d) + float(m) / 60)

	return (lat, lon)

def isFloat(s):
	try:
		float(s)
		return True
	except ValueError:
		return False

def checkin_badge_fmt(badge):
	iconurl = ""
	img = badge.get('image')
	if img is not None:
		iconurl = img['prefix'] + str(img['sizes'][0]) + img['name']

	return """
<p><img src="%s" style="float:left">
You've unlocked the %s badge: 
%s<br style="clear:both">
""" % (iconurl, badge.get('name', ''), badge.get('description', ''))

def checkin_score_fmt(score):
	return """
<p><img src="http://foursquare.com%s" style="float:left">
%s points: %s<br style="clear:both">
""" % (score['icon'], score['points'], score['message'])

def find_notifs(notif, ntype):
	return [n['item'] for n in notif if n['type'] == ntype]

def checkin_fmt(checkin, notif):
	"""
	Format checkin messages.
	"""
	msgs = find_notifs(notif, 'message')
	if len(msgs) > 0:
		s = '<p>%s' % escape(msgs[0]['message'])

	venue = checkin.get('venue')
	if venue is not None:
		s += '<p><a class="button" href="/venue?vid=%s">%s</a><br>%s' % ( 
				venue['id'], escape(venue['name']), addr_fmt(venue))

		location = venue.get('location')
		if location is not None:
			lat = location.get('lat')
			lng = location.get('lng')
			if lat is not None and lng is not None:
				# Add static Google Map to the page.
				s += google_map(lat, lng)

		pcat = get_prim_category(venue.get('categories'))
		if pcat is not None:
			s += category_fmt(pcat)

	mayor = None
	mayors = find_notifs(notif, 'mayorship')
	if len(mayors) > 0:
		mayor = mayors[0]

	if mayor is not None:
		user = mayor.get('user')
		msg = escape(mayor['message'])
		s += '<p>%s' % msg if user is None else """
<p><img src="%s" style="float:left">%s<br style="clear:both">
""" % (user['photo'], msg)

	badges = find_notifs(notif, 'badge')
	if len(badges) > 0:
		s += ''.join([checkin_badge_fmt(b) for b in badges[0].values()])

	scores = find_notifs(notif, 'score')
	if len(scores) > 0:
		s += ''.join([checkin_score_fmt(score) 
			for score in scores[0]['scores']])

	leaderboard = find_notifs(notif, 'leaderboard')
	if len(leaderboard) > 0:
		s += checkin_ldr_fmt(leaderboard[0])

	return s

def checkin_ldr_row_fmt(leader):
	user = leader.get('user', {})
	scores = leader.get('scores', {})
	return """
<p><img src="%s" style="float:left"> #%d: %s %s from %s<br>
%d points, %d checkins, %d max<br style="clear:both">
""" % (user.get('photo', ''),
		leader.get('rank', 0),
		user.get('firstName', ''),
		user.get('lastName', ''),
		user.get('homeCity', ''),
		scores.get('recent', 0),
		scores.get('checkinsCount', 0),
		scores.get('max', 0))

def checkin_ldr_fmt(leaderboard):
	s = ''

	leaders = leaderboard.get('leaderboard', [])
	s += ''.join([checkin_ldr_row_fmt(l) for l in leaders])

	s += '<p>%s' % leaderboard.get('message', '')
	return s

def do_checkin(self, client, vid):
	(lat, lon) = coords(self)

	jsn = call4sq(self, client, 'post', path='/checkins/add',
			params = {
				"venueId" : vid,
				"broadcast" : "public",
				})
	if jsn is None:
		return

	htmlbegin(self, "Check in")
	userheader(self, client, lat, lon)

	response = jsn.get('response')
	if response is None:
		logging.error('Missing response from /checkins/add:')
		logging.error(jsn)
		return jsn

	checkin = response.get('checkin')
	if checkin is None:
		logging.error('Missing checkin from /checkins/add:')
		logging.error(jsn)
		return jsn

	notif = jsn.get('notifications')
	if notif is None:
		logging.error('Missing notifications from /checkins/add:')
		logging.error(jsn)
		return jsn

	self.response.out.write(checkin_fmt(checkin, notif))

	debug_json(self, jsn)
	htmlend(self)

def photo_full_fmt(photo, venue_id = None, checkin_id = None):
	if venue_id:
		backurl = '/venue?vid=%s' % escape(venue_id)
	else:
		backurl = '/comments?chkid=%s' % escape(checkin_id)
	return '<p><a href="%s"><img src="%s"></a><br>' % (
			backurl, photo['url'])

def comment_fmt(comment, checkin, dnow):
	return '<p>%s: %s (%s)<br>%s<br>' % (
			name_fmt(comment['user']),
			comment['text'],
			fuzzy_delta(dnow - datetime.fromtimestamp(comment['createdAt'])),
			del_comment_cmd(checkin, comment),
			)

def photo_fmt(photo, dnow, venue_id = None, checkin_id = None):
	imgurl = photo['url']

	# If multiple sizes are available, then pick the largest photo that is not
	# greater than 150 pixels in width. If none fit, pick the smallest photo.
	if photo['sizes']['count'] > 0:
		_photos = filter(lambda p:p['width'] <= 150, photo['sizes']['items'])
		if _photos:
			imgurl = max(_photos, key = lambda p:p['width'])['url']
		else:
			imgurl = min(photo['sizes']['items'], key = lambda p:p['width'])['url']

	photoparms = { 'photoid' : photo['id'] }
	if venue_id is not None:
		photoparms['venid'] = venue_id
	else:
		photoparms['chkid'] = checkin_id
	photourl = '/photo?%s' % escape(urllib.urlencode(photoparms))

	return '<p>%s:<br><a href="%s"><img src="%s"></a><br>(%s)<br>' % (
			name_fmt(photo['user']),
			photourl,
			imgurl,
			fuzzy_delta(dnow - datetime.fromtimestamp(photo['createdAt'])),
			)

def del_comment_cmd(checkin, comment):
	return '<a class="vbutton" href="/delcomment?chkid=%s&commid=%s">delete</a>' % (
			checkin['id'], comment['id'])

def checkin_comments_fmt(checkin):
	s = ''
	dnow = datetime.utcnow()
	s += '<p></p>' + history_checkin_fmt(checkin, dnow)

	s += '<p>-- %s --' % pluralize(checkin['comments']['count'], 'comment')
	if checkin['comments']['count'] > 0:
		s += ''.join([comment_fmt(c, checkin, dnow) for c in checkin['comments']['items']])

	s += '<p>-- %s --' % pluralize(checkin['photos']['count'], 'photo')
	if checkin['photos']['count'] > 0:
		s += ''.join([photo_fmt(c, dnow, checkin_id = checkin['id']) 
			for c in checkin['photos']['items']])

	return s

