"use strict";

var request = require('request')
  , assert = require('assert');

describe('Circumflex Auth', function() {

  before(function(cb) {
    require('./mock/app')(cb);
  });

  it('detects unauthenticated users', function(cb) {
    request.get('http://localhost:8123/',
      function(err, res, body) {
        if (err) return cb(err);
        assert.equal(body, 'Authenticate, please.');
        cb();
      });
  });

  it('lets users authenticate', function(cb) {
    var jar = request.jar();
    request.post({
      url: 'http://localhost:8123/login',
      followAllRedirects: true,
      form: {
        user: 'joe'
      },
      jar: jar
    }, function(err, res, body) {
      if (err) return cb(err);
      assert.equal(body, 'Hi, Joe Bloggs');
      cb();
    });
  });

});
