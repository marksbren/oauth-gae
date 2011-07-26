from google.appengine.ext import db
class AccessToken(db.Model):
	"""
	Store access tokens indexed by login uuid.
	"""
	uuid = db.StringProperty(required=True)
	token = db.StringProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)

class CoordsTable(db.Model):
	"""
	A table that stores coords associated with each login.
	"""
	uuid = db.StringProperty(required=True)
	coords = db.StringProperty(required=True)
	created = db.DateTimeProperty(auto_now_add=True)