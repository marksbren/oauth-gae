#!/usr/bin/env python

"""
<p>PlainSquare - This webapp is similar to Foursquare's mobile website but
allows manual input of coordinates. That will allow nearest venue searches and
check-ins by phones that do not have GPS.

<p>Input is optimized for handsets without a full keyboard by allowing coordinate entry using only digits. PlainSquare streamlines the check-in process, making the default no-frills action single-click.

<p>PlainSquare uses Foursquare OAuth to log in, so it does not store user passwords. It is written in Python and is meant to be hosted on Google App Engine.

<pre>
Version: 0.0.4
Author: Po Shan Cheah (morton@mortonfox.com)
Source code: <a href="http://code.google.com/p/plainsq/">http://code.google.com/p/plainsq/</a>
Created: January 28, 2011
Last updated: July 21, 2011
</pre>
"""
from config import *
from models import *

from helpers import * #Needs the USER_AGENT variable

class LoginHandler(webapp.RequestHandler):
	"""
	Page that we show if the user is not logged in.
	"""
	def get(self):
		# This page should be cached. So omit the no_cache() call.
		htmlbegin(self, "Log in")

		self.response.out.write("""
<p>In order to use PlainSq features, you need to log in with Foursquare.
<p><a class="button" href="/login2">Log in with Foursquare</a>
""")
		htmlend(self, nologout=True)

class LoginHandler2(webapp.RequestHandler):
	"""
	Second part of login handler. This does the actual login and redirection to
	Foursquare.
	"""
	def get(self):
		self.response.out.write('Logging in to Foursquare...')
		client = newclient()
		self.redirect(client.requestAuth())

class MainHandler(webapp.RequestHandler):
	def get(self):
		no_cache(self)
		(lat, lon) = coords(self)

		client = getclient(self)
		if client is None:
			return

		htmlbegin(self, "Main")

		userid = None
		user = userheader(self, client, lat, lon)
		if user is None:
			# If the users/self query failed then check if we have a saved
			# userid from memcache. If so, then we can still display the menu.
			userid = get_userid(self)
			if userid is None:
				return
		else:
			userid = user['id']
			set_userid(self, userid)
		leaderboard = 'http://foursquare.com/iphone/me?uid=%s' \
				% userid

		self.response.out.write("""
<ol class="menulist">

<li><a class="widebutton" href="/geoloc" accesskey="1">Detect location</a></li>

<li><form class="formbox" action="/coords" method="get">
Enter coordinates: <input class="inputbox" type="text" name="coords" size="8"
accesskey="2"><input class="submitbutton" type="submit" value="Go"></form></li>

<li><a class="widebutton" href="/venues" accesskey="3">Nearest Venues</a></li>

<li><form class="formbox" action="/venues" method="get">
Search Venues: <input class="inputbox" type="text" name="query" size="8"
accesskey="4"><input class="submitbutton" type="submit" value="Search"></form></li>

<li><a class="widebutton" href="/history" accesskey="5">History</a></li>

<li><a class="widebutton" href="/friends" accesskey="6">Find friends</a></li>

<li><form class="formbox" action="/shout" method="post">
Shout: <input class="inputbox" type="text" name="message" size="8" accesskey="7">
<input class="submitbutton" type="submit" value="Shout"></form></li>

<li><a class="widebutton" href="%s" accesskey="8">Leaderboard</a></li>

<li><a class="widebutton" href="/specials" accesskey="9">Specials</a></li>

<li><a class="widebutton" href="/badges" accesskey="0">Badges</a></li>

<li><a class="widebutton" href="/mayor">Mayorships</a></li>

<li><a class="widebutton" href="/debug">Turn debugging %s</a></li>

</ol>

<p>Enter coordinates as a series of digits, e.g.:
<br>
<br>39123457512345 means N 39&deg; 12.345' W 75&deg; 12.345'
<br>391234751234 means N 39&deg; 12.340' W 75&deg; 12.340'
<br>3912375123 means N 39&deg; 12.300' W 75&deg; 12.300'
""" % (leaderboard, "off" if get_debug(self) else "on"))

		htmlend(self)

class OAuthHandler(webapp.RequestHandler):
	"""
	This handler is the callback for the OAuth handshake. It stores the access
	token and secret in cookies and redirects to the main page.
	"""
	def get(self):
		no_cache(self)

		auth_code = self.request.get('code')
		client = newclient()
		client.requestSession(auth_code)

		access_token = client.getAccessToken()

		uuid_str = str(uuid.uuid1())

		# Set the login cookie.
		self.response.headers.add_header(
				'Set-Cookie', 
				'%s=%s; expires=Fri, 31-Dec-2020 23:59:59 GMT' % (
					TOKEN_COOKIE, uuid_str))

		# Add the access token to the database.
		acc = AccessToken(uuid = TOKEN_PREFIX + uuid_str, token = access_token)
		acc.put()

		self.redirect('/')

class LogoutHandler(webapp.RequestHandler):
	"""
	Handler for user logout command.
	"""
	def del_cookie(self, cookie):
		""" 
		Delete cookies by setting expiration to a past date.
		"""
		self.response.headers.add_header(
				'Set-Cookie', 
				'%s=; expires=Fri, 31-Dec-1980 23:59:59 GMT' % cookie)

	def get(self):
		# This page should be cached. So omit the no_cache() call.
		self.del_cookie(TOKEN_COOKIE)
		self.del_cookie(DEBUG_COOKIE)

		htmlbegin(self, "Logout")
		self.response.out.write('<p>You have been logged out')
		htmlend(self, nologout=True)


class VInfoHandler(webapp.RequestHandler):
	"""
	This handler displays info on one venue.
	"""
	def get(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		vid = self.request.get('vid')
		if vid == '':
			self.redirect('/')
			return

		jsn = call4sq(self, client, 'get', path='/venues/%s' % vid)
		if jsn is None:
			return

		htmlbegin(self, "Venue info")
		userheader(self, client, lat, lon)

		resp = jsn.get('response')
		if resp is None:
			logging.error('Missing response from /venues:')
			logging.error(jsn)
			return jsn

		venue = resp.get('venue')
		if venue is None:
			logging.error('Missing venue from /venues:')
			logging.error(jsn)
			return jsn

		self.response.out.write(vinfo_fmt(venue))

		debug_json(self, jsn)
		htmlend(self)

class HistoryHandler(webapp.RequestHandler):
	"""
	Handler for history command.
	"""
	def get(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		jsn = call4sq(self, client, 'get', path='/users/self/checkins',
				params = { 'limit' : '50' })
		if jsn is None:
			return

		htmlbegin(self, "History")
		userheader(self, client, lat, lon)

		resp = jsn.get('response')
		if resp is None:
			logging.error('Missing response from /users/checkins:')
			logging.error(jsn)
			return jsn

		checkins = resp.get('checkins')
		if checkins is None:
			logging.error('Missing checkins from /users/checkins:')
			logging.error(jsn)
			return jsn

		if checkins['count'] == 0:
			self.response.out.write('<p>No check-ins?')
		else:
			dnow = datetime.utcnow()
			self.response.out.write("""
<ul class="vlist">
%s
</ul>
""" % ''.join(
	['<li>%s</li>' % history_checkin_fmt(c, dnow)
		for c in checkins['items']]))

		debug_json(self, jsn)
		htmlend(self)

class DebugHandler(webapp.RequestHandler):
	"""
	Handler for Debug command. Toggle debug mode.
	"""
	def get(self):
		debug = get_debug(self)
		set_debug(self, (0 if debug else 1))
		self.redirect('/')

def badge_fmt(badge):
	iconurl = ""
	img = badge.get('image')
	if img is not None:
		iconurl = img['prefix'] + str(img['sizes'][0]) + img['name']

	unlockstr = ''
	unlocks = badge['unlocks']
	if len(unlocks) > 0:
		checkins = unlocks[0]['checkins']
		if len(checkins) > 0:
			venue = checkins[0].get('venue')
			if venue is not None:
				location = venue['location']
				city = location.get('city', '')
				state = location.get('state', '')
				locstr = ''
				if city != '' or state != '':
					locstr = ' in %s %s' % (city, state)
				unlockstr = """
Unlocked at <a href="/venue?vid=%s">%s</a>%s on %s.
""" % (
		venue['id'], venue['name'], locstr, 
		datetime.fromtimestamp(checkins[0]['createdAt']).ctime())

	desc = badge.get('description')
	if desc is None:
		desc = badge.get('hint', '')

	if unlockstr == '':
		text = '<span class="grayed">%s<br>%s</span>' % (badge['name'], desc)
	else:
		text = '%s<br>%s<br>%s' % (badge.get('name', ''), desc, unlockstr)

	return """
<p><img src="%s" style="float:left"> %s<br style="clear:both">
""" % (iconurl, text)

class BadgesHandler(webapp.RequestHandler):
	"""
	Handler for badges command.
	"""
	def get(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		jsn = call4sq(self, client, 'get', path='/users/self/badges')
		if jsn is None:
			return

		htmlbegin(self, "Badges")
		userheader(self, client, lat, lon, badges=1)

		resp = jsn.get('response')
		if resp is None:
			logging.error('Missing response from /users/badges:')
			logging.error(jsn)
			return jsn

		badges = resp.get('badges')
		if badges is None:
			logging.error('Missing badges from /users/badges:')
			logging.error(jsn)
			return jsn

		if len(badges) == 0:
			self.response.out.write('<p>No badges yet.')
		else:
			self.response.out.write(''.join([
				badge_fmt(b) for b in badges.values()]))

		debug_json(self, jsn)
		htmlend(self)

class MayorHandler(webapp.RequestHandler):
	"""
	Handler for mayor command.
	"""
	def get(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		htmlbegin(self, "Mayorships")

		user = userheader(self, client, lat, lon, mayor=1)
		if user is None:
			return

		mayorships = user.get('mayorships', {})
		count = mayorships.get('count', 0)
		if count == 0:
			self.response.out.write('<p>No mayorships yet.')
		else:
			self.response.out.write(
				'<ol class="numseplist">%s</ol>' % 
				''.join([mayor_venue_fmt(v) for v in mayorships['items']]))

		debug_json(self, user)
		htmlend(self)


class FriendsHandler(webapp.RequestHandler):
	"""
	Handler for Find Friends command.
	"""
	def get(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		jsn = call4sq(self, client, 'get', path='/checkins/recent',
				params = { 'll':'%s,%s' % (lat,lon), 'limit':100 })
		if jsn is None:
			return

		htmlbegin(self, "Find Friends")
		userheader(self, client, lat, lon)

		response = jsn.get('response')
		if response is None:
			logging.error('Missing response from /checkins/recent:')
			logging.error(jsn)
			return jsn

		recent = response.get('recent')
		if recent is None:
			logging.error('Missing recent from /checkins/recent:')
			logging.error(jsn)
			return jsn

		dnow = datetime.utcnow()

		# Sort checkins by distance. If distance is missing,
		# use a very large value.
		recent.sort(key = lambda v: v.get('distance', '1000000'))

		if len(recent) == 0:
			self.response.out.write('<p>No friends?')
		else:
			self.response.out.write("""
<ul class="vlist">
%s
</ul>
""" % ''.join(
	['<li>%s</li>' % friend_checkin_fmt(c, lat, lon, dnow)
		for c in recent]))

		debug_json(self, jsn)
		htmlend(self)

class ShoutHandler(webapp.RequestHandler):
	"""
	This handles user shouts.
	"""
	def post(self):
		self.get()

	def get(self):
		no_cache(self)
		(lat, lon) = coords(self)

		client = getclient(self)
		if client is None:
			return

		message = self.request.get('message')
		if message == '':
			self.redirect('/')
			return

		jsn = call4sq(self, client, 'post', path='/checkins/add',
				params = {
					"shout" : message,
					"ll" : '%s,%s' % (lat, lon),
					"broadcast" : "public",
					})
		if jsn is None:
			return

		htmlbegin(self, "Shout")
		userheader(self, client, lat, lon)

		notif = jsn.get('notifications')
		if notif is None:
			logging.error('Missing notifications from /checkins/add:')
			logging.error(jsn)
			return jsn

		self.response.out.write('<p>%s' % escape(notif[0]['item']['message']))

		debug_json(self, jsn)
		htmlend(self)

class VenuesHandler(webapp.RequestHandler):
	"""
	Handler for venue search.
	"""
	def post(self):
		self.get()

	def get(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		# query is an optional keyword search parameter. If it is not present,
		# then just do a nearest venues search.
		query = self.request.get('query')

		parms = { "ll" : '%s,%s' % (lat, lon), "limit" : 50, 'v' : '20110615' }
		if query != '':
			parms['query'] = query

		jsn = call4sq(self, client, 'get', path='/venues/search',
				params = parms)
		if jsn is None:
			return

		htmlbegin(self, "Venue search")
		userheader(self, client, lat, lon)

		response = jsn.get('response')
		if response is None:
			logging.error('Missing response from /venues/search:')
			logging.error(jsn)
			return jsn

		self.response.out.write("""
<form style="margin:0; padding:0;" action="/addvenue" method="post"><p>
Add venue here and check in: <input type="text" name="vname" size="15"><input type="submit" value="Add Venue"></p></form>

<p>""" + venues_fmt(response, lat, lon))

		debug_json(self, jsn)
		htmlend(self)


class CoordsHandler(webapp.RequestHandler):
	"""
	This handles user-input coordinates. Sets the location to 
	those coordinates and brings up the venue search page.
	"""
	def get(self):
		self.post()

	def post(self):
		no_cache(self)

		htmlbegin(self, "Change location")

		geolat = self.request.get('geolat')
		geolong = self.request.get('geolong')

		# geolat/geolong are float parameters. Move to those coordinates.
		if isFloat(geolat) and isFloat(geolong):
			set_coords(self, geolat, geolong)
			self.redirect('/venues')
			return

		coordinput = self.request.get('coords')

		# Extract digits. Ignore all other characters.
		instr = re.sub(r'[^0-9]', '', coordinput)

		if len(instr) >= 4:
			(lat, lon) = parse_coord(instr)
			set_coords(self, lat, lon)
			self.redirect('/venues')
		else:
			self.response.out.write(
					'<p><span class="error">Bad input coords: %s</span>'
					% escape(coordinput))

		htmlend(self)


class CheckinHandler(webapp.RequestHandler):
	"""
	This handles user checkins by venue ID.
	"""
	def get(self):
		self.post()

	def post(self):
		no_cache(self)

		client = getclient(self)
		if client is None:
			return

		vid = self.request.get('vid')
		if vid == '':
			self.redirect('/')
			return

		do_checkin(self, client, vid)

class AddVenueHandler(webapp.RequestHandler):
	"""
	Add a venue at the current coordinates with no address information.
	"""
	# This is technically not idempotent but allow both methods anyway.
	def get(self):
		self.post()

	def post(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		vname = self.request.get('vname')
		if vname == '':
			self.redirect('/')
			return

		jsn = call4sq(self, client, 'post', path='/venues/add',
				params = {"name" : vname, "ll" : '%s,%s' % (lat, lon)})
		if jsn is None:
			return

		response = jsn.get('response')
		if response is None:
			logging.error('Missing response from /venues/add:')
			logging.error(jsn)
			return jsn

		venue = response.get('venue')
		if venue is None:
			logging.error('Missing venue from /venues/add:')
			logging.error(jsn)
			return jsn

		do_checkin(self, client, venue['id'])

class AboutHandler(webapp.RequestHandler):
	"""
	Handler for About command.
	"""
	def get(self):
		# This page should be cached. So omit the no_cache() call.
		htmlbegin(self, "About")
		self.response.out.write(__doc__)
		htmlend(self, noabout=True, nologout=True)

class GeoLocHandler(webapp.RequestHandler):
	"""
	Geolocation Handler. Will attempt to detect location using HTML5
	Geolocation API and set our coordinates accordingly.
	"""
	def get(self):
		# This page should be cached. So omit the no_cache() call.
		htmlbegin(self, "Detect Location")
		self.response.out.write("""
<noscript>
<p><span class="error">No Javascript support or Javascript disabled.</span> Can't detect location.
</noscript>
<p><span id="output">&nbsp;</span>
<script type="text/javascript">
function show(msg) {
	var out = document.getElementById('output');
	out.innerHTML = msg;
}

function error(msg) {
	show('<span class="error">' + msg + '</span>');
}

function error_callback(err) {
	switch (err.code) {
	case err.PERMISSION_DENIED:
		error('No permission to get location: ' + err.message);
		break;
	case err.POSITION_UNAVAILABLE:
		error('Could not get location: ' + err.message);
		break;
	case err.TIMEOUT:
		error('Network timeout: ' + err.message);
		break;
	default:
		error('Unknown error: ' + err.message);
		break;
	}
}

function success_callback(pos) {
	show('Detected coordinates: ' + 
		pos.coords.latitude + ',' + pos.coords.longitude);
	// Redirect to our coordinates handler once we have the info.
	window.location = '/coords?geolat=' + pos.coords.latitude + 
		'&geolong=' + pos.coords.longitude
}

if (navigator.geolocation) {
	show('Detecting location...');
	navigator.geolocation.getCurrentPosition(
		success_callback, error_callback, { timeout: 30000 });
}
else {
	error('Geolocation API not supported in this browser.')
}
</script>
""")

		htmlend(self)

class PurgeHandler(webapp.RequestHandler):
	"""
	Purge old database entries from CoordsTable and AuthToken.
	"""
	def get(self):
		no_cache(self)

		cutoffdate = (date.today() - timedelta(days=30)).isoformat()
		creatclause = "WHERE created < DATE('%s')" % cutoffdate

		htmlbegin(self, 'Purge old database entries')

		query = AccessToken.gql(creatclause)
		count = 0
		for result in query:
			result.delete()
			count += 1
		self.response.out.write('<p>Deleted %d old entries from AccessToken table' % count)

		query = CoordsTable.gql(creatclause)
		count = 0
		for result in query:
			result.delete()
			count += 1
		self.response.out.write('<p>Deleted %d old entries from CoordsTable table' % count)

		memcache.flush_all()
		self.response.out.write('<p>Flushed memcache')

		htmlend(self)

class CheckinLong2Handler(webapp.RequestHandler):
	"""
	Continuation of CheckinLongHandler after the user submits the
	checkin form with options.
	"""
	def post(self):
		self.get()

	def get(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		vid = self.request.get('vid')
		if vid == '':
			self.redirect('/')
			return

		shout = self.request.get('shout')
		private = int(self.request.get('private'))
		twitter = int(self.request.get('twitter'))
		facebook = int(self.request.get('facebook'))

		broadstrs = []
		if private:
			broadstrs += 'private'
		else:
			broadstrs += 'public'
		if twitter:
			broadstrs += 'twitter'
		if facebook:
			broadstrs += 'facebook'

		jsn = call4sq(self, client, 'post', path='/checkins/add',
				params = {
					'venueId' : vid,
					'shout' : shout,
					'broadcast' : ','.join(broadstrs),
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

class CheckinLongHandler(webapp.RequestHandler):
	"""
	This handles user checkin with options.
	"""
	def get(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		vid = self.request.get('vid')
		vname = self.request.get('vname')

		jsn = call4sq(self, client, 'get', '/settings/all')
		if jsn is None:
			return

		htmlbegin(self, "Check in")
		userheader(self, client, lat, lon)

		response = jsn.get('response')
		if response is None:
			logging.error('Missing response from /settings/all:')
			logging.error(jsn)
			return jsn

		settings = response.get('settings')
		if settings is None:
			logging.error('Missing settings from /settings/all:')
			logging.error(jsn)
			return jsn

		private = 0
		twitter = 0
		facebook = 0

		if settings['sendToTwitter']:
			twitter = 1
		if settings['sendToFacebook']:
			facebook = 1

		self.response.out.write('<p>Check in @ %s' % escape(vname))

		sel = 'selected="selected"'

		self.response.out.write("""
<form action="/checkin_long2" method="post">
Shout (optional): <input class="inputbox" type="text" name="shout" size="15"><br>
<input type="hidden" value="%s" name="vid">
<input class="formbutton" type="submit" value="check-in"><br>
<select name="private">
<option value="1" %s>Don't show your friends</option>
<option value="0" %s>Show your friends</option>
</select><br>
<select name="twitter">
<option value="0" %s>Don't send to Twitter</option>
<option value="1" %s>Send to Twitter</option>
</select><br>
<select name="facebook">
<option value="0" %s>Don't send to Facebook</option>
<option value="1" %s>Send to Facebook</option>
</select><br>
</form>
"""
			% ( escape(vid), private and sel, private or sel,
				twitter or sel, twitter and sel,
				facebook or sel, facebook and sel ))

		debug_json(self, jsn)
		htmlend(self)

class SpecialsHandler(webapp.RequestHandler):
	"""
	Retrieves a list of nearby specials.
	"""
	def get(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		jsn = call4sq(self, client, 'get', '/specials/search',
				params = { 
					'll' : '%s,%s' % (lat, lon),
					'limit' : 50
					})
		if jsn is None:
			return

		htmlbegin(self, "Specials")
		userheader(self, client, lat, lon)

		response = jsn.get('response')
		if response is None:
			logging.error('Missing response from /specials/search:')
			logging.error(jsn)
			return jsn

		specials = response.get('specials')
		if specials is None:
			logging.error('Missing specials from /specials/search:')
			logging.error(jsn)
			return jsn

		if specials['count'] == 0:
			self.response.out.write('<p>No specials nearby')
		else:
			self.response.out.write(specials_fmt(specials['items']))

		debug_json(self, jsn)
		htmlend(self)

class DelCommentHandler(webapp.RequestHandler):
	"""
	Delete a comment from a check-in.
	"""
	def get(self):
		self.post()

	def post(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		checkin_id = self.request.get('chkid')
		comment_id = self.request.get('commid')
		if checkin_id == '' or comment_id == '':
			self.redirect('/')
			return

		jsn = call4sq(self, client, 'post', 
				'/checkins/%s/deletecomment' % escape(checkin_id),
				params = { 'commentId' : comment_id }
				)
		if jsn is None:
			return

		self.redirect('/comments?chkid=%s' % escape(checkin_id))

class AddCommentHandler(webapp.RequestHandler):
	"""
	Add a comment to a check-in.
	"""
	def get(self):
		self.post()

	def post(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		checkin_id = self.request.get('chkid')
		text = self.request.get('text')
		if checkin_id == '':
			self.redirect('/')
			return

		if text:
			jsn = call4sq(self, client, 'post', 
					'/checkins/%s/addcomment' % escape(checkin_id),
					params = { 'text' : text }
					)
			if jsn is None:
				return

		self.redirect('/comments?chkid=%s' % escape(checkin_id))

class AddPhotoHandler(webapp.RequestHandler):
	"""
	Add a photo to a check-in.
	"""
	def get(self):
		self.post()

	def post(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		checkin_id = self.request.get('chkid')
		venue_id = self.request.get('venid')
		photo = self.request.get('photo')

		if checkin_id == '' and venue_id == '':
			self.redirect('/')
			return

		if photo:
			# Resize photo and convert to JPEG.
			photo = images.resize(photo, 800, 800, images.JPEG)

			params = { 'photo' : photo }
			if venue_id:
				params['venueId'] = venue_id
			else:
				params['checkinId'] = checkin_id

			jsn = call4sq(self, client, 'post', '/photos/add', params)
			if jsn is None:
				return

		if venue_id:
			self.redirect('/venue?vid=%s' % escape(venue_id))
		else:
			self.redirect('/comments?chkid=%s' % escape(checkin_id))
			
class PhotoHandler(webapp.RequestHandler):
	"""
	View full-size version of a photo.
	"""
	def get(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		checkin_id = self.request.get('chkid')
		venue_id = self.request.get('venid')
		photo_id = self.request.get('photoid')
		if photo_id == '':
			self.redirect('/')
			return

		jsn = call4sq(self, client, 'get', '/photos/%s' % escape(photo_id))
		if jsn is None:
			return

		htmlbegin(self, "Photo")
		userheader(self, client, lat, lon)

		response = jsn.get('response')
		if response is None:
			logging.error('Missing response from /photos:')
			logging.error(jsn)
			return jsn

		photo = response.get('photo')
		if photo is None:
			logging.error('Missing photo from /photos:')
			logging.error(jsn)
			return jsn

		self.response.out.write(photo_full_fmt(photo, 
			checkin_id = checkin_id, venue_id = venue_id))

		debug_json(self, jsn)
		htmlend(self)


class CommentsHandler(webapp.RequestHandler):
	"""
	View comments on a check-in.
	"""
	def get(self):
		no_cache(self)

		(lat, lon) = coords(self)
		client = getclient(self)
		if client is None:
			return

		checkin_id = self.request.get('chkid')
		if checkin_id == '':
			self.redirect('/')
			return

		jsn = call4sq(self, client, 'get', '/checkins/%s' % escape(checkin_id))
		if jsn is None:
			return

		htmlbegin(self, "Checkin Comments")
		userheader(self, client, lat, lon)

		response = jsn.get('response')
		if response is None:
			logging.error('Missing response from /checkins:')
			logging.error(jsn)
			return jsn

		checkin = response.get('checkin')
		if checkin is None:
			logging.error('Missing checkin from /checkins:')
			logging.error(jsn)
			return jsn

		self.response.out.write(checkin_comments_fmt(checkin))

		self.response.out.write("""
<p>
<form style="margin:0; padding:0;" action="/addcomment" method="post">
<input class="inputbox" type="text" name="text" size="15"><br>
<input type="hidden" value="%s" name="chkid">
<input class="formbutton" type="submit" value="Add comment"><br>
</form>
""" % escape(checkin_id))

		self.response.out.write("""
<p>
<form style="margin:0; padding:0;" enctype="multipart/form-data" action="/addphoto" method="post">
<input class="inputbox" type="file" name="photo"><br>
<input type="hidden" value="%s" name="chkid">
<input class="formbutton" type="submit" value="Add JPEG photo"><br>
</form>
""" % escape(checkin_id))

		debug_json(self, jsn)
		htmlend(self)

class UnknownHandler(webapp.RequestHandler):
	"""
	Handle bad URLs.
	"""
	def get(self, unknown_path):
		errorpage(self, 'Unknown URL: /%s' % escape(unknown_path), 404)

def main():
	# logging.getLogger().setLevel(logging.DEBUG)
	application = webapp.WSGIApplication([
		('/', MainHandler),
		('/login', LoginHandler),
		('/login2', LoginHandler2),
		('/oauth', OAuthHandler),
		('/logout', LogoutHandler),
		('/venue', VInfoHandler),
		('/history', HistoryHandler),
		('/debug', DebugHandler),
		('/badges', BadgesHandler),
		('/mayor', MayorHandler),
		('/friends', FriendsHandler),
		('/shout', ShoutHandler),
		('/venues', VenuesHandler),
		('/coords', CoordsHandler),
		('/checkin', CheckinHandler),
		('/addvenue', AddVenueHandler),
		('/about', AboutHandler),
		('/geoloc', GeoLocHandler),
		('/purge', PurgeHandler),
		('/checkin_long', CheckinLongHandler),
		('/checkin_long2', CheckinLong2Handler),
		('/specials', SpecialsHandler),
		('/comments', CommentsHandler),
		('/addcomment', AddCommentHandler),
		('/delcomment', DelCommentHandler),
		('/addphoto', AddPhotoHandler),
		('/photo', PhotoHandler),
		('/(.*)', UnknownHandler),
		], debug=True)
	util.run_wsgi_app(application)


if __name__ == '__main__':
	main()

# vim:set tw=0:
