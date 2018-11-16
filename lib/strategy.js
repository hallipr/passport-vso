/**
 * Module dependencies.
 */
var util = require('util')
  , uid = require('uid2')
  , OAuth2Strategy = require('passport-oauth2')
  , Profile = require('./profile')
  , InternalOAuthError = require('passport-oauth2').InternalOAuthError
  , VsoRestApiError = require('./errors/vsorestapierror')
  , url = require('url')
  , querystring = require('querystring');


/**
 * `Strategy` constructor.
 *
 * The Visual Studio Online authentication strategy authenticates requests by delegating
 * to Visual Studio Online using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Visual Studio Online application's client ID
 *   - `clientSecret`  your Visual Studio Online application's client secret
 *   - `callbackURL`   URL to which Visual Studio Online will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new VsoStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/vso/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://app.vssps.visualstudio.com/oauth2/authorize';
  options.tokenURL = options.tokenURL || 'https://app.vssps.visualstudio.com/oauth2/token';
  options.sessionKey = options.sessionKey || ('vso:' + url.parse(options.authorizationURL).hostname);
  
  OAuth2Strategy.call(this, options, verify);
  this._oauth2.useAuthorizationHeaderforGET(true);
  this._oauth2.setAuthMethod('Bearer');
  this._oauth2.getOAuthJwtAccessToken = getOAuthJwtAccessToken;
  
  this.name = 'vso';
  this._userProfileURL = options.userProfileURL || 'https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=1.0';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


/**
 * Retrieve user profile from Visual Studio Online.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `vso`
 *   - `id`               the user's Visual Studio Online ID
 *   - `displayName`      the user's full name
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.get(this._userProfileURL, accessToken, function (err, body, res) {
    var json;
    if (err) {
      if (err.data) {
        try {
          json = JSON.parse(err.data);
        } catch (_) {}
      }
        
      if (json && json.error) {
        return done(new VsoRestApiError(json.error.message, json.error.code));
      }
      return done(new InternalOAuthError('Failed to fetch user profile', err));
    }
    
    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse user profile'));
    }
    
    var profile = Profile.parse(json);
    profile.provider  = 'vso';
    profile._raw = body;
    profile._json = json;
    
    done(null, profile);
  });
};

Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;
  
  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new OAuth2Strategy.AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }

  var callbackURL = resolveCallbackURL(req, options.callbackURL || this._callbackURL);

  if (req.query && req.query.code) {
    var code = req.query.code;
    
    if (this._state) {
      if (!req.session) { return this.error(new Error('VSO Strategy requires session support when using state. Did you forget app.use(express.session(...))?')); }
      
      var key = this._key;
      if (!req.session[key]) {
        return this.fail({ message: 'Unable to verify authorization request state.' }, 403);
      }
      var state = req.session[key].state;
      if (!state) {
        return this.fail({ message: 'Unable to verify authorization request state.' }, 403);
      }
      
      delete req.session[key].state;
      if (Object.keys(req.session[key]).length === 0) {
        delete req.session[key];
      }
      
      if (state !== req.query.state) {
        return this.fail({ message: 'Invalid authorization request state.' }, 403);
      }
    }

    var params = this.tokenParams(options);
    params.grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    params.redirect_uri = callbackURL;
    
    this._oauth2.getOAuthJwtAccessToken(code, params,
      function(err, accessToken, refreshToken, params) {
        if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }
        
        self._loadUserProfile(accessToken, function(err, profile) {
          if (err) { return self.error(err); }
          
          function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(info); }
            self.success(user, info);
          }
          
          try {
            var arity = self._verify.length;
            if (self._passReqToCallback) {
              if (arity == 6) {
                self._verify(req, accessToken, refreshToken, params, profile, verified);
              } else { // arity == 5
                self._verify(req, accessToken, refreshToken, profile, verified);
              }
            } else {
              if (arity == 5) {
                self._verify(accessToken, refreshToken, params, profile, verified);
              } else { // arity == 4
                self._verify(accessToken, refreshToken, profile, verified);
              }
            }
          } catch (ex) {
            return self.error(ex);
          }
        });
      }
    );
  } else {
    var params = this.authorizationParams(options);
    params.response_type = 'Assertion';
    params.redirect_uri = callbackURL;
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }
    var state = options.state;
    if (state) {
      params.state = state;
    } else if (this._state) {
      if (!req.session) { return this.error(new Error('VSO Strategy requires session support when using state. Did you forget app.use(express.session(...))?')); }
      
      var key = this._key;
      state = uid(24);
      if (!req.session[key]) { req.session[key] = {}; }
      req.session[key].state = state;
      params.state = state;
    }
    
    var location = this._oauth2.getAuthorizeUrl(params);
    this.redirect(location);
  }
};

Strategy.prototype.refreshAccessToken = function(req, refreshToken, callback) {
  var params = {
    grant_type: 'refresh_token',
    redirect_uri: resolveCallbackURL(req, this._callbackURL)
  };
  return this._oauth2.getOAuthJwtAccessToken(refreshToken, params, callback);
};

function getOAuthJwtAccessToken(code, params, callback) {
  params.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
  params.client_assertion = this._clientSecret;
  params.assertion = code;

  var post_data= querystring.stringify( params );
  
  var post_headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
   
  this._request("POST", this._getAccessTokenUrl(), post_headers, post_data, null, function(error, data, response) {
    if( error )  callback(error);
    else {
      var results = JSON.parse( data );
      var access_token = results.access_token;
      var refresh_token = results.refresh_token;
      delete results.refresh_token;
      callback(null, access_token, refresh_token, results); // callback results =-=
    }
  });
};

function originalURL(req, options) {
  options = options || {};
  var app = req.app;
  if (app && app.get && app.get('trust proxy')) {
    options.proxy = true;
  }
  var trustProxy = options.proxy;
  
  var proto = (req.headers['x-forwarded-proto'] || '').toLowerCase()
    , tls = req.connection.encrypted || (trustProxy && 'https' == proto.split(/\s*,\s*/)[0])
    , host = (trustProxy && req.headers['x-forwarded-host']) || req.headers.host
    , protocol = tls ? 'https' : 'http'
    , path = req.url || '';
  return protocol + '://' + host + path;
}

function resolveCallbackURL(req, callbackURL) {
  if (req && callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }
  return callbackURL
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
