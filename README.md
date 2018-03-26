# Passport-SteemConnect
A SteemConnect authentication strategy for Passport.

This module lets you authenticate using SteemConnect in your Node.js applications.
By plugging into Passport, SteemConnect authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/) and [NextAuth](https://github.com/iaincollins/next-auth)


## Install

    $ npm i passport-steemconnect --save

## Usage

#### Configure Strategy

The SteemConnect authentication strategy authenticates users using a third-party
account and OAuth 2.0 tokens.  The User uses The Standard OAuth 2.0 endpoints for SteemConnect, as well as
the client identifer and secret, are specified as options.  The strategy
requires a `verify` callback, which receives an access token and profile,
and calls `cb` providing a user.

```js
 * Options:
 *
 *   - `authorizationURL`  URL used to obtain an authorization grant
 *   - `tokenURL`          URL used to obtain an access token
 *   - `clientID`          identifies client to service provider
 *   - `clientSecret`      secret used to establish ownership of the client identifer
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *   - `scope`             ['vote','comment','offline',]
 *
 *
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
```

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'steemconnect'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

```js
app.get('/auth/example',
  passport.authenticate('steemconnect'));

app.get('/auth/example/callback',
  passport.authenticate('steemconnect', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/');
  });
```

## Related Modules
- [passport-google-oauth2](https://github.com/mstade/passport-google-oauth2) Google (OAuth 2.0) authentication strategy for Passport and Node.js.
- [passport-oauth1](https://github.com/jaredhanson/passport-oauth1) — OAuth 1.0 authentication strategy
- [passport-http-bearer](https://github.com/jaredhanson/passport-http-bearer) — Bearer token authentication strategy for APIs
- [OAuth2orize](https://github.com/jaredhanson/oauth2orize) — OAuth 2.0 authorization server toolkit

## License

[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2018 Sean Warren [http://doyoubelieve.me/](http://doyoubelieve.me)
