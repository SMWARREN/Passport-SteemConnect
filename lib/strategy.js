// Load modules.
//
const fetch = require('isomorphic-fetch');
const steemconnect = require('./steemconnect/sc2');
const passport = require('passport-strategy');
const url = require('url');
const util = require('util');
const utils = require('./utils');
const { OAuth2 } = require('oauth');
const NullStateStore = require('./state/null');
const SessionStateStore = require('./state/session');
const AuthorizationError = require('./errors/authorizationerror');
const TokenError = require('./errors/tokenerror');
const InternalOAuthError = require('./errors/internaloautherror');


/**
 * Creates an instance of `SteemConnectStrategy`.
 *
 * The SteemConnect authentication strategy authenticates requests using the OAuth
 * 2.0 framework.
 *
 * Passport - SteemConnect provides a facility for delegated authentication, whereby users can
 * authenticate SteemConnect.  Delegating in
 * this manner involves a sequence of events, including redirecting the user to
 * the third-party service for authorization.  Once authorization has been
 * granted, the user is redirected back to the application and an authorization
 * code can be used to obtain credentials.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile, done) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *
 *   - `authorizationURL`  URL used to obtain an authorization grant
 *   - `tokenURL`          URL used to obtain an access token
 *   - `clientID`          identifies client to service provider
 *   - `clientSecret`      secret used to establish ownership of the client identifer
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *   - `scope`             ['vote','comment','offline',]
 * Examples:
 *
 *     passport.use(new SteemConnectStrategy({
 *         authorizationURL: 'https://steemconnect.com/oauth2/authorize',
 *         tokenURL: 'https://steemconnect.com/oauth2/token',
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret',
 *         callbackURL: 'http://localhost:3000/auth/oauth/steemconnect/callback',
 *         scope: ["offline","vote"],
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
class SteemConnectStrategy {
  constructor(options, verify) {
    if (typeof options === 'function') {
      verify = options;
      options = undefined;
    }

    options = options || {};

    if (!verify) { throw new TypeError('SteemConnectStrategy requires a verify callback'); }
    if (!options.authorizationURL) { throw new TypeError('SteemConnectStrategy requires a authorizationURL option'); }
    if (!options.tokenURL) { throw new TypeError('SteemConnectStrategy requires a tokenURL option'); }
    if (!options.clientID) { throw new TypeError('SteemConnectStrategy requires a clientID option'); }

    passport.Strategy.call(this);
    this.name = 'steemconnect';
    this._verify = verify;

    // NOTE: The _steemconnect property is considered "protected".  Subclasses are
    //       allowed to use it when making protected resource requests to retrieve
    //       the user profile.
    this._steemconnect = new OAuth2(
      options.clientID, options.clientSecret,
      '', options.authorizationURL, options.tokenURL, options.customHeaders);

    this._callbackURL = options.callbackURL;
    this._scope = options.scope;
    this.scope = options.scope;
    this._scopeSeparator = options.scopeSeparator || ' ';
    this._key = options.sessionKey || (`steemconnect:${url.parse(options.authorizationURL).hostname}`);

    if (options.store) {
      this._stateStore = options.store;
    } else if (options.state) {
      this._stateStore = new SessionStateStore({ key: this._key });
    } else {
      this._stateStore = new NullStateStore();
    }
    this._trustProxy = options.proxy;
    this._passReqToCallback = options.passReqToCallback;
    this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;

    // Inherit from `passport.Strategy`.
    util.inherits(SteemConnectStrategy, passport.Strategy);
  }

  /**
    * Authenticate request by delegating to a service provider using OAuth 2.0.
    *
    * @param {Object} req
    * @api protected
    */
  authenticate(req, options) {
    options = options || {};
    const self = this;

    if (req.query && req.query.error) {
      if (req.query.error == 'access_denied') {
        return this.fail({ message: req.query.error_description });
      }
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }

    let callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      var parsed = url.parse(callbackURL);
      if (!parsed.protocol) {
        // The callback URL is relative, resolve a fully qualified URL from the
        // URL of the originating request.
        callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
      }
    }

    const meta = {
      authorizationURL: this._steemconnect._authorizeUrl,
      tokenURL: this._steemconnect._accessTokenUrl,
      clientID: this._steemconnect._clientId,
    };

    if (req.query && req.query.code) {
      function loaded(err, ok, state) {
        if (err) { return self.error(err); }
        if (!ok) {
          return self.fail(state, 403);
        }

        const code = req.query.code;

        const params = self.tokenParams(options);
        params.grant_type = 'authorization_code';
        if (callbackURL) { params.redirect_uri = callbackURL; }


        self.getOAuthAccessToken(
          code, params,
          (err, accessToken, refreshToken, params) => {
            if (err === []) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }

            self._loadUserProfile(accessToken, (err, profile) => {
              if (err) { return self.error(err); }

              function verified(err, user, info) {
                if (err) { return self.error(err); }
                if (!user) { return self.fail(info); }

                info = info || {};
                if (state) { info.state = state; }
                self.success(user, info);
              }

              try {
                if (self._passReqToCallback) {
                  var arity = self._verify.length;
                  if (arity == 6) {
                    self._verify(req, accessToken, refreshToken, params, profile, verified);
                  } else { // arity == 5
                    self._verify(req, accessToken, refreshToken, profile, verified);
                  }
                } else {
                  var arity = self._verify.length;
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
          },
        );
      }

      var state = req.query.state;
      try {
        var arity = this._stateStore.verify.length;
        if (arity == 4) {
          this._stateStore.verify(req, state, meta, loaded);
        } else { // arity == 3
          this._stateStore.verify(req, state, loaded);
        }
      } catch (ex) {
        return this.error(ex);
      }
    } else {
      const params = this.authorizationParams(options);
      params.response_type = 'code';
      if (callbackURL) { params.redirect_uri = callbackURL; }
      let scope = options.scope || this._scope;
      if (scope) {
        if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
        params.scope = scope;
      }

      var state = options.state;
      if (state) {
        params.state = state;

        var parsed = url.parse(this._steemconnect._authorizeUrl, true);
        utils.merge(parsed.query, params);
        parsed.query.client_id = this._steemconnect._clientId;
        delete parsed.search;
        const location = url.format(parsed);
        this.redirect(location);
      } else {
        function stored(err, state) {
          if (err) { return self.error(err); }

          if (state) { params.state = state; }
          const parsed = url.parse(self._steemconnect._authorizeUrl, true);
          utils.merge(parsed.query, params);
          parsed.query.client_id = self._steemconnect._clientId;
          delete parsed.search;
          const location = url.format(parsed);
          self.redirect(location);
        }

        try {
          var arity = this._stateStore.store.length;
          if (arity == 3) {
            this._stateStore.store(req, meta, stored);
          } else { // arity == 2
            this._stateStore.store(req, stored);
          }
        } catch (ex) {
          return this.error(ex);
        }
      }
    }
  }
  /**
    * Retrieve users oauth2 information from the service provider.
    *
    * Passport-SteemConenct  overrrides this function in
    * order to load the user's profile from the service provider.  This assists
    * applications (and users of those applications) in the initial registration
    * process by automatically submitting required information.
    *
    * @param {String} code
    * @param {Object} params
    * @param {Function} function
    * @api protected
    */

  getOAuthAccessToken(code, params, callback) {
    const scope = this.scope ? this.scope.join(',') : 'offline,vote';
    return new Promise((resolve, reject) => {
      fetch(`https://steemconnect.com/api/oauth2/token?refresh_token=${code}&scope=${scope}`, {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        method: 'POST',
        body: JSON.stringify({ client_secret: 'c0cdc0a66e3bcc592cd1d157fd5078d56562c9e7e949365c' }),
      })
        .then(r => r.json()).then((steemConnectObj) => {
          resolve(steemConnectObj);
        }).catch((err) => {
          reject({ error: err.error_description });
        });
    }).then((res) => {
      callback(null, res.access_token, res.refresh_token, params);
    }).catch((err) => {
      callback(err, null, null, null, params);
    });
  }

  /**
    * Retrieve user profile from service provider.
    *
    * OAuth 2.0-based authentication strategies can overrride this function in
    * order to load the user's profile from the service provider.  This assists
    * applications (and users of those applications) in the initial registration
    * process by automatically submitting required information.
    *
    * @param {String} accessToken
    * @param {Function} done
    * @api protected
    */
  userProfile(accessToken, done) {
    const profile = {};
    steemconnect.setAccessToken(accessToken);
    steemconnect.me((err, result) => {
      if (!err) {
        profile.id = result.account.id;
        profile.displayName = result.name;
        profile.profile_image = null;

        const steemprofile = JSON.parse(result.account.json_metadata);
        try {
          profile.photo = steemprofile.profile.profile_image;
        } catch (e) {
          profile.photo = null;
        }
        done(null, profile);
      }
    });
  }
  /**
    * Parse error response from OAuth 2.0 endpoint.
    *
    * OAuth 2.0-based authentication strategies can overrride this function in
    * order to parse error responses received from the token endpoint, allowing the
    * most informative message to be displayed.
    *
    * If this function is not overridden, the body will be parsed in accordance
    * with RFC 6749, section 5.2.
    *
    * @param {String} body
    * @param {Number} status
    * @return {Error}
    * @api protected
    */
  parseErrorResponse(body, status) {
    const json = JSON.parse(body);
    if (json.error) {
      return new TokenError(json.error_description, json.error, json.error_uri);
    }
    return null;
  }

  /**
    * Load user profile, contingent upon options.
    *
    * @param {String} accessToken
    * @param {Function} done
    * @api private
    */
  _loadUserProfile(accessToken, done) {
    const self = this;

    function loadIt() {
      return self.userProfile(accessToken, done);
    }
    function skipIt() {
      return done(null);
    }

    if (typeof this._skipUserProfile === 'function' && this._skipUserProfile.length > 1) {
      // async
      this._skipUserProfile(accessToken, (err, skip) => {
        if (err) { return done(err); }
        if (!skip) { return loadIt(); }
        return skipIt();
      });
    } else {
      const skip = (typeof this._skipUserProfile === 'function') ? this._skipUserProfile() : this._skipUserProfile;
      if (!skip) { return loadIt(); }
      return skipIt();
    }
  }

  /**
    * Create an OAuth error.
    *
    * @param {String} message
    * @param {Object|Error} err
    * @api private
    */
  _createOAuthError(message, err) {
    let e;
    if (err.statusCode && err.data) {
      try {
        e = this.parseErrorResponse(err.data, err.statusCode);
      } catch (_) {}
    }
    if (!e) { e = new InternalOAuthError(message, err); }
    return e;
  }
  /**
 * Return extra parameters to be included in the authorization request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting authorization.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
  authorizationParams(options) {
    return {};
  }

  /**
 * Return extra parameters to be included in the token request.
 *
 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
 * included when requesting an access token.  Since these parameters are not
 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
 * strategies can overrride this function in order to populate these parameters
 * as required by the provider.
 *
 * @return {Object}
 * @api protected
 */
  tokenParams(options) {
    return {};
  }
}


// Expose constructor.
module.exports = SteemConnectStrategy;
