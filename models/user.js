'use strict';

var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
var jwt = require('jwt-simple');

const JWT_SECRET = 'hey whats up hello';

var User;

// Creates a User Schema. This will be the basis of how user data is stored in the db
var userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  location: {type: [Number], required: true}, // [Long, Lat]
  created_at: {type: Date, default: Date.now},
  updated_at: {type: Date, default: Date.now}
});

// Sets the created_at parameter equal to the current time
userSchema.pre('save', function(next){
    now = new Date();
    this.updated_at = now;
    if(!this.created_at) {
        this.created_at = now
    }
    next();
});

// Indexes this schema in 2dsphere format (critical for running proximity searches)
userSchema.index({location: '2dsphere'});

userSchema.statics.authMiddleware = function(req, res, next) {
  var token = req.cookies.fettycookie;
  try {
    var payload = jwt.decode(token, JWT_SECRET);
  } catch(err) {
    return res.clearCookie('fettycookie').status(401).send();
  }
  // we have a valid token

  User.findById(payload.userId).select({password: 0}).exec(function(err, user) {
    if(err || !user) {
      return res.clearCookie('fettycookie').status(401).send(err);
    }
    // the user exists!
    req.user = user; // making the user document availble to the route
    next(); // everything is good, and the request can continue
  });
};

userSchema.methods.generateToken = function() {
  // `this` is the document you are calling the method on
  var payload = {
    userId: this._id,
    iat: Date.now()  // issued at time
  };
  // generate a token
  var token = jwt.encode(payload, JWT_SECRET);
  return token;
};

userSchema.statics.authenticate = function(userObj, cb) {
  User.findOne({username: userObj.username}, function(err, dbUser) {
    if(err || !dbUser) {
      return cb("Authentication failed.");
    }
    bcrypt.compare(userObj.password, dbUser.password, function(err, isGood) {
      if(err || !isGood) {
        return cb("Authentication failed.");
      }
      dbUser.password = null;
      cb(null, dbUser);
    });
  });
};

userSchema.statics.register = function(userObj, cb) {
  bcrypt.hash(userObj.password, 10, function(err, hash) {
    if(err) {
      return cb(err);
    }
    User.create({
      username: userObj.username,
      password: hash
    }, function(err, user) {
      if(err) {
        cb(err);
      } else {
        user.password = null;
        cb(err, user);
      }
    });
  });
};

User = mongoose.model('User', userSchema);

module.exports = User;
