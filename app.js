 var express = require('express');
var path = require('path');
var favicon = require('static-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');
var mongoose = require('mongoose');
var nodemailer = require('nodemailer');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var bcrypt = require('bcrypt-nodejs');
var async = require('async');
var crypto = require('crypto');
var flash = require('express-flash');

var app = express();
mongoose.connect('mongodb://ctf2_t6_dev:QeBP7mFLvqL407tE@cluster0-shard-00-00-gptnr.mongodb.net:27017,cluster0-shard-00-01-gptnr.mongodb.net:27017,cluster0-shard-00-02-gptnr.mongodb.net:27017/test?ssl=true&replicaSet=Cluster0-shard-0&authSource=admin');

// Middleware
app.set('port', process.env.PORT || 8080);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(favicon());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const passwordValidator = require('./password-validator');

app.use(session({ 
  secret: process.env.SESSION_SECRET_KEY,
  resave: true,
  saveUninitialized: true
}));

app.use(flash());

app.use(passport.initialize());
app.use(passport.session());


passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
  }, function(username, password, done) {
  User.findOne({ email: username }, function(err, user) {
    if (err) return done(err);
    if (!user) return done(null, false, { message: 'Incorrect email.' });
    user.comparePassword(password, function(err, isMatch) {
      if (isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password.' });
      }
    });
  });
}));

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// User schema
var userSchema = new mongoose.Schema({
  //username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  salt: { type: String }
});

userSchema.pre('save', function(next) {
  var user = this;
  var SALT_FACTOR = 5;

  if (!user.isModified('password')) return next();

  var uniqueSalt =" "; 
  var charset = "abcdefghijklmnopqrstuvwxyz0123456789";
    
  for( var i=0; i < 5; i++ )
      uniqueSalt += charset.charAt(Math.floor(Math.random() * charset.length));
      
  var hash = crypto.createHash('md5').update(uniqueSalt + user.password).digest("hex");
  user.password = hash;
  user.salt = uniqueSalt;
  next();
});

userSchema.methods.comparePassword = function(candidatePassword, cb) {
  var candidateHash = crypto.createHash('md5').update(this.salt + candidatePassword).digest("hex");
  cb(null, (candidateHash === this.password));
};

var User = mongoose.model('User', userSchema);

// Routes
app.get('/', function(req, res){
  res.render('index', {
    title: 'HackMe',
    user: req.user
  });
});

app.get('/login', function(req, res) {
  res.render('login', {
    user: req.user
  });
});

app.get('/signup', function(req, res) {
  res.render('signup', {
    user: req.user
  });
});

app.get('/success', function(req, res) {
  if (!req.user) {
    req.flash('error', 'Please signup first.');
    return res.redirect('/signup');
  }
  res.render('success', {
    title: 'Sign Up Successful!',
    user: req.user
  });
});

app.get('/failure', function(req, res) {
  if (!req.headers.referer) {
    req.flash('error', 'Please login first.');
    return res.redirect('/login');
  }
  res.render('failure', {
  });
});

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

app.get('/forgot', function(req, res) {
  res.render('forgot', {
    user: req.user
  });
});

app.post('/login', function(req, res, next) {
  passport.authenticate('local', function(err, user, info) {
    if (err) return next(err)
    if (!user) {
      return res.redirect('/failure')
    }
    req.logIn(user, function(err) {
      if (err) return next(err);
      return res.redirect('/');
    });
  })(req, res, next);
});

app.post('/signup', function(req, res) {
  var user = new User({
      // username: req.body.username,
      email: req.body.email,
      password: req.body.password
    });

  // TODO: Check password criteria
  var result = passwordValidator(user.password);
  console.log('passwordValidator result', result);

  var isUSCEmail = /@usc.edu\s*$/.test(user.email);
  console.log('isUSCEmail', isUSCEmail);

  if(!result.valid) {
    console.log('error', result.message);
    req.flash('error', result.message);
    return res.redirect('/signup');
  }
  else if(!isUSCEmail) {
    console.log('error NOT USC EMAIL');
    req.flash('error', 'Must use USC Email address ( @usc.edu )');
    return res.redirect('/signup');
  }
  else {
    user.save(function(err) {
      if (err) {
        console.log(err);
        req.flash('error', err.message);
        return res.redirect('/signup');
      }
      else {
        req.logIn(user, function(err) {
          if (err) {
            console.log(err);
            req.flash('error', err.message);
            return res.redirect('/signup');
          }
          else res.redirect('/success');
        });
      }
    });
  }
});

app.post('/forgot', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', 'No account with that email address exists.');
          return res.redirect('/forgot');
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'USC430.T6.CTF2@gmail.com',
          pass: 'c8dfafad-5e5b-426b-816d-833983fe3510'
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'passwordreset@csci430Team6.com',
        subject: 'Team6 Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + '13.57.208.67' + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      transporter.sendMail(mailOptions, function(err) {
        req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        done(err, 'done');
      });
    }
  ], function(err) {
    if (err) return next(err);
    res.redirect('/forgot');
  });
});

app.get('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/forgot');
    }
    res.render('reset', {
      user: req.user
    });
  });
});

app.post('/reset/:token', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }
        
        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        // TODO: Check password criteria
        var result = passwordValidator(req.body.password);
        console.log(result);
        if(!result.valid) {
          req.flash('error', result.message);
          var route = '/reset/' + req.params.token;
          return res.redirect(route);
        }
        else {
          user.save(function(err) {
            req.logIn(user, function(err) {
              done(err, user);
            });
          });
        }
      });
    },
    function(user, done) {
      var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'USC430.T6.CTF2@gmail.com',
          pass: 'c8dfafad-5e5b-426b-816d-833983fe3510'
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'passwordreset@demo.com',
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      transporter.sendMail(mailOptions, function(err) {
        req.flash('success', 'Success! Your password has been changed.');
        done(err);
      });
    }
  ], function(err) {
    res.redirect('/');
  });
});

app.listen(app.get('port'), function() {
  console.log('Express server listening on port ' + app.get('port'));
});