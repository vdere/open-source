'use strict';

var mongoose = require('mongoose');
var bcrypt = require('bcrypt');
var Schema = mongoose.Schema;
var crypto = require('crypto');
var config = require('./../../config/environment');

var UserSchema = new Schema({
  userName: {type : String,unique : true},
  role: {
    type: String,
    default: 'customer',
    enum:['admin','customer']
  },
  hashedPassword: String,
  salt: String,
  status : {type:String,default:"Active" ,enum:['Active','InActive']}
});

/**
 * Virtuals
 */
UserSchema
  .virtual('password')
  .set(function(password) {
    if (this.isNew && !password) {
      this.invalidate('password', 'can not be blank');
    } else if (!(/^(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[a-z])(?=.*[A-Z])[a-zA-Z0-9!@#$%^&*]{6,20}$/).test(password)) {
      this.invalidate('password', 'should contain at least 1 uppercase letter, 1 lowercase letter, 1 number, 1 special character and length must be between 6 and 20');
    } else {
      this.salt = '2Y7xk5vrs5DeCcSdinRVKQ==';
      this.hashedPassword = this.encryptPassword(password);
    }
  });

// Public profile information
UserSchema
  .virtual('profile')
  .get(function() {
    return {
      'name': this.name,
      'role': this.role
    };
  });

/**
 * Validations
 */
var validatePresenceOf = function(value) {
  return value && value.length;
};

UserSchema.path('userName').validate(function(username){
   var alphaNumeric = /^[A-Za-z0-9]+$/;
   return username.match(alphaNumeric);
},'Invalid Username')

/**
 * Pre-save hook
 */
UserSchema
  .pre('save', function(next) {
    if (!this.isNew) return next();

    if (!validatePresenceOf(this.hashedPassword))
      next(new Error('Invalid password'));
    else
      next();
  });

/**
 * Methods
 */
UserSchema.methods = {

  /**
   * Authenticate - check if the passwords are the same
   *
   * @param {String} plainText
   * @return {Boolean}
   * @api public
   */

  authenticate: function(plainText) {
    return bcrypt.compare(this.encryptPassword(plainText), this.hashedPassword);
  },

  /**
   * Encrypt password
   *
   * @param {String} password
   * @return {String}
   * @api public
   */
  encryptPassword: function(password) {
    if (!password || !this.salt) return '';
    var salt = new Buffer(this.salt, 'base64');
    return crypto.pbkdf2Sync(password, salt, config.pbkdf.iterations, config.pbkdf.keylen).toString('base64');
  }
};

var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

exports.setup = function (User, config) {
  const errorMsg = 'Something went wrong, please try again';

  passport.use(new LocalStrategy({
      usernameField: 'username',
      passwordField: 'password' // this is the virtual field on the model
    },
    function(username, password, done) {
      User.findOne({
        userName: username.toLowerCase()
      }, function(err, user) {
        if (err) return done(err);

        if (!user || user.status === "InActive") {
           user =new User();
          var isAuthenticated=user.authenticate(Math.random().toString(36).slice(2));
          return done(null, false, errorMsg);
        }
        else if (!user.authenticate(password)) {
          return done(null, false, errorMsg);
        }
        return done(null, user);
      });
    }
  ));
};

