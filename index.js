'use strict';

var bcrypt = require('bcrypt-nodejs');
var mongoose = require('mongoose');
var semver = require('semver');

module.exports = function(schema, options) {

  options = options || {};

  // Get array of encrypted field(s)
  var fields = options.fields || options.field || [];
  if (typeof fields === 'string') {
    fields = [ fields ];
  }

  // Scan schema for fields marked as encrypted
  schema.eachPath(function(name,type) {
    if (type.options.bcrypt && fields.indexOf(name) < 0) {
      fields.push(name);
    }
  });

  // Use default 'password' field if no fields specified
  if (fields.length === 0)
    fields.push('password');

  // Get encryption rounds or use defaults
  var rounds = options.rounds || 0;

  // Add properties and verifier functions to schema for each encrypted field
  fields.forEach(function(field){

    // Setup field name for camelcasing
    var path = field.split('.');
    var fieldName = path.map(function(word){
      return word[0].toUpperCase() + word.slice(1);
    }).join('');

    // Define encryption function
    schema.statics['encrypt' + fieldName] = function(value, cb) {
      return encrypt(field, value, cb);
    };

    // Define async verification function
    schema.methods['verify' + fieldName] = function(value, cb) {
      if (Promise) {
        var self = this;
        return new Promise(function(resolve,reject) {
          bcrypt.compare(value, self.get(field), function(err, valid) {
            if (cb) {
              cb(err, valid);
            }
            if (err) {
              reject(err);
            } else {
              resolve(valid);
            }
          });
        });
      } else {
        return bcrypt.compare(value, this.get(field), cb);
      }
    };

    // Define sync verification function
    schema.methods['verify' + fieldName + 'Sync'] = function(value) {
      return bcrypt.compareSync(value, this.get(field));
    };

    // Add field to schema if not already defined
    if (!schema.path(field)) {
      var pwd = { };
      var nested = pwd;
      for (var i = 0; i < path.length-1; ++i) {
        nested[path[i]] = {}
        nested = nested[path[i]];
      }
      nested[path[path.length-1]] = { type: String };
      schema.add(pwd);
    }
  });

  // Hash all modified encrypted fields upon saving the model
  schema.pre('save', function preSavePassword(next) {
    var model = this;
    var changed = [];

    // Determine list of encrypted fields that have been modified
    fields.forEach(function(field){
      if (model.isModified(field)) {
          changed.push(field);
      }
    });

    // Create/update hash for each modified encrypted field
    var count = changed.length;
    if (count > 0) {
      changed.forEach(function(field){
        encrypt(field, model.get(field), function(err, hash) {
          if (err) return next(err);
          model.set(field, hash);
          if (--count === 0)
            next();
        });
      });
    } else {
      next();
    }
  });

  function preUpdate(next) {
    var query = this;
    var update = query.getUpdate();
    if (update.$set) {
      update = update.$set;
    }
    var changed = [];
    fields.forEach(function(field){
      if (update[field]) {
        changed.push(field);
      }
    });
    var count = changed.length;
    if (count > 0) {
      changed.forEach(function(field){
        encrypt(field, update[field], function(err, hash) {
          if (err) return next(err);
          update[field] = hash;
          if (--count === 0) {
            next();
          }
        });
      });
    } else {
        next();
    }
  }

  if (semver.gte(mongoose.version, "4.1.3")) {
      schema.pre('update', preUpdate);
      schema.pre('findOneAndUpdate', preUpdate);
  }

  function encrypt(field, value, cb) {
    if (Promise) {
      return new Promise(function(resolve,reject) {
        bcrypt.genSalt(schema.path(field).options.rounds || rounds, function(err, salt) {
          if (cb && err) {
            cb(err, salt);
          }
          if (err) {
            reject(err);
          } else {
            bcrypt.hash(value, salt, null, function(err, result) {
              if (cb) {
                cb(err, result);
              }
              if (err) {
                reject(err);
              } else {
                resolve(result);
              }
            });
          }
        });
      })
    } else {
      bcrypt.genSalt(schema.path(field).options.rounds || rounds, function(err, salt) {
        if (err) {
          cb(err);
        } else {
          bcrypt.hash(value, salt, null, cb);
        }
      });
    }
  }
};
