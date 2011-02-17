"""
The MIT License

Copyright (c) 2011 @yasuki (http://maarui.doorblog.jp)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

from google.appengine.api import users
from google.appengine.api import urlfetch
from google.appengine.ext import webapp
from google.appengine.ext import db
from google.appengine.ext.webapp.util import run_wsgi_app

import cgi
import oauth

REQUEST_TOKEN_URL = 'https://sandbox.evernote.com/oauth'
ACCESS_TOKEN_URL =  'https://sandbox.evernote.com/oauth'
AUTHORIZATION_URL = 'https://sandbox.evernote.com/OAuth.action'

CALLBACK_URL = 'http://localhost:8080/oauth/token_ready' 
#CALLBACK_URL = 'http://<YOUR App>.appspot.com/oauth/token_ready' 

CONSUMER_KEY = '<YOUR API KEY>'
CONSUMER_SECRET = '<YOUR SECRET>' 

""" AuthToken Model in Google DataStore """
class OAuthTokenDB(db.Model):
  user = db.UserProperty(required=True,auto_current_user=True)
  token_key = db.StringProperty(required=True)
  edam_shard = db.StringProperty()
  edam_userId = db.IntegerProperty()
  date = db.DateTimeProperty(auto_now_add=True)

""" Title Page """
class TopPage(webapp.RequestHandler): 
  def get(self): 
    """ Google Login """
    user = users.get_current_user()

    if user:
      googleLogin = ("Welcome, %s! (<a href=\"%s\">sign out</a>)<BR>" %
                    (user.nickname(), users.create_logout_url(self.request.uri)))
    else:
      googleLogin = ("<a href=\"%s\">Sign in or register</a>.<BR>" %
                    users.create_login_url(self.request.uri))

    """ Doy you have the Access Token? """
    accessToken = get_token_from_datastore()

    if accessToken == None:
      evernoteLogin = ("<a href=\"/oauth\">Evernote OAuth Login</a>") 
    else:
      evernoteLogin = ("Evernote Logined: %s<br><a href='/oauth/delete_token'>delete token</a>" % accessToken.token_key )

    """ Display """
    self.response.headers['Content-Type'] = 'text/html'
    self.response.out.write('<html><body>')
    self.response.out.write("%s<br>" % googleLogin)
    self.response.out.write("%s<br>" % evernoteLogin)
    self.response.out.write("</body></html>")


""" Get OAuth Request Token """
class GetOAuthRequest(webapp.RequestHandler): 
  def get(self): 
    user = users.get_current_user()

    """ OAuth Request token (first) making """
    callbackurl = CALLBACK_URL
    consumer = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET) 
    oauth_request = oauth.OAuthRequest.from_consumer_and_token(
        consumer,
        token=None,
        http_url=REQUEST_TOKEN_URL,
        callback=callbackurl,
        parameters=None) 
    signature_method = oauth.OAuthSignatureMethod_HMAC_SHA1() 
    oauth_request.sign_request(signature_method, consumer, None ) 
    url = oauth_request.to_url() 
    result = urlfetch.fetch(url) 

    if result.status_code == 200: 
      token = oauth.OAuthToken.from_string(result.content) 

      """ Authorized request token (second) making """
      oauth_request = oauth.OAuthRequest.from_token_and_callback (
          token=token,
          callback=CALLBACK_URL,
          http_url=AUTHORIZATION_URL) 
      url = oauth_request.to_url() 
      self.redirect(url) 
    else: 
      self.redirect('/error') 


""" Get OAuth Access Token , Exchange Request Token to Access Token """
class GetOAuthAccess(webapp.RequestHandler): 
  def get(self): 
    user = users.get_current_user()

    try:
      verifier=self.request.get("oauth_verifier")
    except KeyError:
      self.redirect("/error")

    key=self.request.get("oauth_token")
    token = oauth.OAuthToken(key,"dummy") 
    consumer = oauth.OAuthConsumer(CONSUMER_KEY,CONSUMER_SECRET) 
    oauth_request = oauth.OAuthRequest.from_consumer_and_token(
        consumer, 
        token=token, 
        verifier=verifier,
        http_url=ACCESS_TOKEN_URL) 

    signature_method = oauth.OAuthSignatureMethod_PLAINTEXT() 
    oauth_request.sign_request(signature_method, consumer, token) 
    url = oauth_request.to_url() 
    result = urlfetch.fetch(url) 

    if result.status_code == 200: 
      """ Token Store to Google DataStore """
      parts=cgi.parse_qs(str(result.content) )
      db = OAuthTokenDB(
        user = user,
        token_key = parts.get("oauth_token")[0],
        edam_shard = parts.get("edam_shard")[0],
        edam_userId = int( parts.get("edam_userId")[0] )
        )
      db.put()
      self.redirect('/') 
    else: 
      self.redirect('/error') 

class DeleteToken(webapp.RequestHandler): 
  def get(self): 
    result = get_token_from_datastore()
    if result:
      result.delete()
    self.redirect('/')
 
class ErrorPage(webapp.RequestHandler): 
  def get(self): 
      self.response.out.write('error request token<br><a href="/">Top</a>') 

def get_token_from_datastore():
  """ search from DataStore """
  user = users.get_current_user()
  query = db.Query(OAuthTokenDB)
  query.filter('user = ', user)
  result = query.get()
  return result
 
def main(): 
  application = webapp.WSGIApplication([ 
    ('/', TopPage), 
    ('/error', ErrorPage), 
    ('/oauth/delete_token', DeleteToken), 
    ('/oauth', GetOAuthRequest), 
    ('/oauth/token_ready', GetOAuthAccess), 
    ('/oauth/main', TopPage), 
  ], debug=True) 
  run_wsgi_app(application)
  #wsgiref.handlers.CGIHandler().run(application) 

if __name__ == '__main__': 
  main() 

