# Simple Auth Middleware for Express

**Important!** This library relies on [alternative session API](https://github.com/inca/alt-session).

A very simple usage:

```
// Mock users database

var USERS = {
  'joe': {
    id: 'joe',
    name: 'Joe Bloggs'
  }
};

var AUTH = {
  getUserId: function(user) {
    return user.id;
  },
  findUserById: function(id, cb) {
    cb(null, USERS[id]);
  }
};

// App middleware

app.use(require('alt-session')({ ... }));
app.use(require('alt-auth')(AUTH);

app.get('/', function(req, res, next) {
  if (!req.principal) {
    req.rememberLocation();
    res.redirect('/login');
  } else res.send('Hi, ' + req.principal.name);
});

app.get('/login', function(req, res, next) {
  res.send('Authenticate, please.');
});

app.post('/login', function(req, res, next) {
  AUTH.findUserById(req.getString('user'), function(err, user) {
    if (err) return next(err);
    if (!user) return res.sendStatus(404);
    // Check password, etc.
    req.login(user, function(err) {
      if (err) return next(err);
      res.redirect(req.lastLocation());
    });
  });
});

```
