var routilCookie = require('routil-cookie');
var url = require('url');
var request = require('request');
var async = require('async');
var cookieSign = require('cookie-signature');

var getCookie = routilCookie.getCookie;
var setCookie = routilCookie.setCookie;
var cookieName = 'simple_github_oauth';

var redirect = function (url, response) {
  response.statusCode = 302;
  response.setHeader('Location', url);
  response.end();
};

var toFunction = function (str) {
  return function () {
    return str;
  };
};

module.exports = function (clientId, clientSecret, config) {
  var scope = (config.team || config.organization) ? 'read:org' : 'public';
  var secret = config.secret || Math.random().toString();
  var state = Math.random().toString();
  var userAgent = config.userAgent || 'github-auth';
  var redirectUri = config.redirectUri || '';
  var accessToken;

  if (typeof redirectUri !== 'function') redirectUri = toFunction(redirectUri);

  var getRequest = function (url, cb) {
    request(url + '?access_token=' + accessToken, {
      headers: {
        'User-Agent': userAgent
      }
    }, cb);
  };

  var getUser = function (callback) {
    getRequest('https://api.github.com/user', function (err, res, body) {
      if (err) {
        return callback(err);
      }
      var userInfo;
      try {
        userInfo = JSON.parse(body);
      } catch (e) {
        return callback(new Error(body), null);
      }
      callback(null, userInfo.login);
    });
  };


  var getTeamId = function (cb) {
    getRequest('https://api.github.com/orgs/' + config.organization + '/teams', function (err, res, body) {
      if (err) return cb(err);
      if (res.statusCode >= 300) return cb(new Error('Get all teams failed'));
      var teams;
      try {
        teams = JSON.parse(body);
      }
      catch (e) {
        return cb(new Error(body), null);
      }

      var teamId = teams.filter(function (x) {
        return x.name === config.team;
      })[0].id;
      cb(null, teamId);
    });
  };

  var isInTeam = function (ghusr, callback) {
    if (!config.organization) return callback(new Error('The organization is required to validate the team.'));
    if (!config.team) return callback(new Error('The team is required.'));

    getTeamId(function (err, tid) {
      if (err) return callback(null, false);
      getUsersOnTeam(tid, function (err, users) {
        if (err) return callback(null, false);
        callback(null, users.indexOf(ghusr) !== -1);
      });
    });
  };

  var isInOrganization = function (callback) {
    getRequest('https://api.github.com/user/orgs', function (err, res, body) {
      if (err) {
        return callback(err);
      }

      var loginedUserOrgs;
      try {
        loginedUserOrgs = JSON.parse(body);
      } catch (e) {
        return callback(new Error(body), null);
      }

      if (!Array.isArray(loginedUserOrgs)) {
        return callback(null, false);
      }

      var loginedUserOrgNames = loginedUserOrgs.map(function (obj) {
        return obj.login;
      });
      var authorized = loginedUserOrgNames.indexOf(config.organization) !== -1;

      callback(null, authorized);
    });
  };

  var lastGhUpdate = 0;
  var authUsers = [];
  var tenMinutes = 1000 * 60 * 10;

  var getUsersOnTeam = function (teamId, cb) {
    if ((new Date().getTime() - lastGhUpdate) < tenMinutes) return cb(null, authUsers);
    lastGhUpdate = new Date().getTime();
    getRequest('https://api.github.com/teams/' + teamId + '/members', function (err, res, body) {
      if (err) return cb(err);
      if (res.statusCode >= 300) return cb(new Error('get teams memebers failed'));
      var usrsObj = JSON.parse(body);
      authUsers = usrsObj.map(function (x) {
        return x.login;
      });
      cb(null, authUsers);
    });
  };

  var githubOauthUrl = function (req) {
    return 'https://github.com/login/oauth/authorize?client_id=' + clientId + '&scope=' + scope + '&redirect_uri=' + redirectUri(req) + '&state=' + state;
  };

  var login = function (req, res, next) {
    redirect(githubOauthUrl(req), res);
  };

  var logout = function (req, res, next) {
    setCookie(res, cookieName, '');
    next();
  };

  return {
    decodeCookie: function (cookie) {
      var val = cookie.match('(^|; )' + cookieName + '=([^;]*)');
      val = val[2];
      val = unescape(val);
      return cookieSign.unsign(val, secret) || null;
    },
    authenticate: function (req, res, next) {
      req.github = {};

      var cookie = getCookie(req, cookieName);
      var unsignedCookie = cookie ? cookieSign.unsign(cookie, secret) : false;
      if (unsignedCookie) {
        req.github.authenticated = true;
        req.github.user = unsignedCookie;
        return next();
      }
      var parsedUrl = url.parse(req.url, true);
      if (!parsedUrl.query.code) {
        return redirect(githubOauthUrl(req), res);
        return next();
      }

      if (parsedUrl.query.state !== state) {
        req.github.authenticated = false;
        return next();
      }

      request.post('https://github.com/login/oauth/access_token', {
        headers: {
          'User-Agent': userAgent
        },
        form: {
          client_id: clientId,
          client_secret: clientSecret,
          code: parsedUrl.query.code,
          redirect_uri: config.redirect_uri,
          state: state
        }
      }, function (err, response, body) {
        if (err) {
          return next(err);
        }

        accessToken = url.parse('/?' + body, true).query.access_token; // covert to query and parse to object

        getUser(function (err, ghusr) {
          if (err) return next(err);

          var checks = [];

          if (config.organization) checks.push(function (cb) {
            isInOrganization(cb);
          });
          if (config.team) checks.push(function (cb) {
            isInTeam(ghusr, cb);
          });

          async.parallel(checks, function (err, results) {
            if (err) return next(err);
            if (results.length === 0) return next(new Error('You have to add either users, team, or organizations to the config'));

            var auth = results.every(function (el) {
              return el;
            });

            if (!auth) {
              req.github.authenticated = false;
              req.github.user = ghusr;
              return next();
            }
            var opts = {};
            if (config.maxAge) opts.expires = new Date(Date.now() + config.maxAge);
            setCookie(res, cookieName, cookieSign.sign(ghusr, secret), opts);
            req.github.user = ghusr;
            req.github.authenticated = true;
            next();
          });
        });
      });
    },
    login: login,
    logout: logout
  };
};