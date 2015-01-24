'use strict';

var _ = require('underscore');

/**
 * Simple session-based authentication middleware.
 *
 * Must be used after cookie parser and alt-session middleware.
 *
 * Available options:
 *
 *   * `getUserId` — `function(user) { return user.id }`
 *   * `findUserById` — `function(id, cb)`, where `cb` is a `function(err, user)`
 *   * `defaultLocation` — where to redirect the user after login (default is `/`)
 *
 * To allow "Remember me" functionality provide `options.persistence` object (see below).
 *
 * @param options
 * @returns {Function} Middleware function
 */
module.exports = function(options) {

  /**
   * Returns a random ASCII-compliant string of specified length.
   *
   * @param length
   */
  function randomString(length) {
    var result = 0;
    for (var i = 0; i < length; i++)
      result += String.fromCharCode(65 + Math.floor(Math.random() * 58));
    return result;
  }

  /**
   * To allow "Remember me" the `options.persistence` object
   * must be provided with four methods:
   *
   *   * `saveToken: function(user, token, cb)`
   *   * `hasToken: function(user, token, cb)`
   *   * `dropToken: function(user, token, cb)`
   *   * `clearTokens: function(user, cb)`
   */
  var persistence = options.persistence;
  if (persistence) {
    // Check that all methods exist
    ['saveToken', 'hasToken', 'dropToken', 'clearTokens']
      .forEach(function(method) {
        if (typeof(persistence[method]) != 'function')
          throw new Error('conf.auth.persistence.' + method + ' is not a function');
      });
    // Configure default cookie
    persistence.cookie = _.extend({
      name: 'at',
      maxAge: 30 * 24 * 60 * 60 * 1000,
      signed: true
    }, persistence.cookie);
  }

  return function auth(req, res, next) {

    if (!req.session) {
      throw new Error('alt-session is required for alt-auth middleware.')
    }

    /**
     * Associates current session with specified `user`.
     *
     * Uses `conf.auth.getUserId(user)` function to map user to its ID.
     *
     * @param user {*} User object (database record, document, whatever)
     * @param cb {Function} Callback
     */
    req.login = function(user, cb) {
      req.session.set('authPrincipalId', options.getUserId(user).toString(), cb);
    };

    /**
     * Stores a persistent cookie for "Remember me" authentication.
     *
     * @param user {*} User object
     * @param cb {Function} Callback
     */
    req.persistLogin = function(user, cb) {
      if (!persistence)
        throw new Error('Persistent auth requires additional configuration.');
      // Generate a token
      var token = randomString(32);
      // Store it
      persistence.saveToken(user, token, function(err) {
        if (err) return cb(err);
        // Add a cookie
        var cookieName = persistence.cookie.name;
        var cookieValue = options.getUserId(user) + ':' + token;
        res.cookie(cookieName, cookieValue, persistence.cookie);
        // Store the token in session
        req.session.set('authPersistenceToken', token, function(err) {
          if (err) return cb(err);
          // Return this token
          cb(null, token);
        });
      });
    };

    /**
     * Removes an association between current session and authenticated user.
     *
     * @param cb {Function} Callback
     */
    req.logout = function(cb) {
      // Only destroy the session if not persistent
      if (!persistence)
        return req.session.invalidate(cb);
      // Drop persistence token and cookie
      res.clearCookie(persistence.cookie.name);
      req.session.get('authPersistenceToken', function(err, token) {
        if (err) return cb(err);
        if (req.principal && token)
          persistence.dropToken(req.principal, token, function(err) {
            if (err) return cb(err);
            req.session.invalidate(cb);
          });
        else req.session.invalidate(cb);
      });
    };

    /**
     * Stores current location (URL) in a cookie. Used to redirect
     * users back after successful authentication.
     */
    req.rememberLocation = function() {
      if (req.method.toLowerCase() == 'get' && !req.xhr) {
        var url = req.protocol + "://" + req.hostname;
        url += req.originalUrl || req.url;
        res.cookie('lastLocation', url);
      }
    };

    /**
     * Returns the URL previously saved with `req.rememberLocation`.
     *
     * Default location, which is returned in case `req.rememberLocation` was not
     * called before, is configured via `conf.auth.defaultLocation`.
     *
     * @returns {*|string} URL or default location
     */
    req.lastLocation = function() {
      return req.cookies.lastLocation || options.defaultLocation || '/';
    };

    /**
     * Attempts to populate the `req.principal` with currently logged
     * authentication identity.
     *
     * @param cb {Function} Callback
     */
    req.trySessionLogin = function(cb) {
      req.session.get('authPrincipalId', function(err, userId) {
        if (err) return cb(err);
        if (!userId) return cb();
        options.findUserById(userId, function(err, user) {
          if (err) return cb(err);
          if (!user)
            return req.session.remove('authPrincipalId', cb);
          req.principal = res.locals.principal = user;
          return cb();
        });
      });
    };

    /**
     * Attempts to authenticate using a cookie which is supposed to
     * be previously set via `req.persistLogin`.
     *
     * @param cb {Function} Callback
     */
    req.tryPersistentLogin = function(cb) {
      function unauthenticated() {
        res.clearCookie(persistence.cookie.name);
        return cb();
      }
      // Read data from the cookie
      var cookieValue = req.signedCookies[persistence.cookie.name];
      if (!cookieValue) return cb();
      var userId = cookieValue.substring(0, cookieValue.indexOf(':'));
      var token = cookieValue.substring(cookieValue.indexOf(':') + 1);
      if (!userId)
        return unauthenticated();
      // Attempt to find a user
      options.findUserById(userId, function(err, user) {
        if (err) return cb(err);
        if (!user) return unauthenticated();
        // See if user really owns the token
        persistence.hasToken(user, token, function(err, owns) {
          if (err) return cb(err);
          if (!owns) return unauthenticated();
          // Log him in
          req.login(user, function(err) {
            if (err) return cb(err);
            req.trySessionLogin(cb);
          });
        });
      });
    };

    /**
     * Middleware body.
     */
    req.trySessionLogin(function(err) {
      if (err) return next(err);
      if (persistence)
        req.tryPersistentLogin(next);
      else next();
    });

  };

};
