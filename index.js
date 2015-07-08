'use strict';

var bcrypt = require('bcrypt-nodejs');
var ROUNDS = 10;
var mcrypter = require('./lib/mcrypter');


var mongooseBcrypt = function(schema, options) {

    options = options || {};

    // Get array of encrypted field(s)
    var fields = options.fields || options.field || [];
    if (typeof fields == 'string') {
        fields = [fields];
    }

    // Scan schema for fields marked as encrypted
    schema.eachPath(function(name,type) {
        if (type.options.bcrypt)
            if (fields.indexOf(name) < 0)
                fields.push(name);
    });

    // Use default 'password' field if no fields specified
    if (fields.length === 0)
        fields.push('password');

    // Get encryption rounds or use defaults
    var rounds = options.rounds || ROUNDS;

    // Add properties and verifier functions to schema for each encrypted field
    fields.forEach(function(field){

        // Setup field name for camelcasing
        var fieldName = field[0].toUpperCase() + field.slice(1);

        // Define async verification function
        schema.methods['verify' + fieldName] = function(password, cb) {
            return bcrypt.compare(password, this[field], cb);
        };

        // Add field to schema if not already defined
        if (!schema.path(field)) {
            var pwd = { };
            pwd[field] = { type: String };
            schema.add(pwd);
        }
    });

    schema.methods.getEncrypted = function(field, cb) {
        var fieldRounds;
        var schemaField = schema.path(field);
        if (!schemaField) {
            return new Promise(function(resolve, reject) {
                reject(new Error('Invalid field `' + field + '`'));
            });
        }
        fieldRounds = schemaField.options.rounds || rounds;
        return mcrypter.encrypt(this[field], fieldRounds).then(function(hash) {
            if (typeof cb === 'function') {
                cb(null, hash);
            }
            return hash;
        }, function(err) {
            if (typeof cb === 'function') {
                cb(err);
            }
            return err;
        });
    };

    // Hash all modified encrypted fields upon saving the model
    schema.pre('save', function preSavePassword(next) {
        var model = this;
        var modified = fields.filter(function(field){
            return model.isModified(field);
        }).map(function(field) {
            var fieldRounds = schema.path(field).options.rounds || rounds;
            return mcrypter.encrypt(model[field], fieldRounds).then(function(hash) {
                model[field] = hash;
            });
        });

        Promise.all(modified).then(next).catch(next);
    });
};

module.exports = mongooseBcrypt;
