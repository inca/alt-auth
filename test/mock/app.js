'use strict';

var app = require('express')();

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

app.use(require('cookie-parser')('alt-auth'));
app.use(require('expressr')());
app.use(require('alt-session').mock());
app.use(require('../../index')(AUTH));

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
    req.login(user, function(err) {
      if (err) return next(err);
      res.redirect(req.lastLocation());
    });
  });
});

module.exports = function(cb) {
  require('http').createServer(app).listen(8123, cb);
};

