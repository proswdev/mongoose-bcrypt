'use strict';

var bcrypt = require('bcrypt-nodejs');

// Add Array.forEach support for older javascript versions
if (!Array.prototype.forEach)
{
    Array.prototype.forEach = function(fun /*, thisp*/)
    {
        var len = this.length;
        if (typeof fun != "function")
            throw new TypeError();

        var thisp = arguments[1];
        for (var i = 0; i < len; i++)
        {
            if (i in this)
                fun.call(thisp, this[i], i, this);
        }
    };
}

module.exports = function(schema, options) {

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
    var rounds = options.rounds || 0;

    // Add properties and verifier functions to schema for each encrypted field
    fields.forEach(function(field){

        // Setup field name for camelcasing
        var fieldName = field[0].toUpperCase() + field.slice(1);

        // Define encryption function
        schema.statics['encrypt' + fieldName] = function(value, cb) {
            return encrypt(field, value, cb);
        };

        // Define async verification function
        schema.methods['verify' + fieldName] = function(value, cb) {
            return bcrypt.compare(value, this[field], cb);
        };

        // Define sync verification function
        schema.methods['verify' + fieldName + 'Sync'] = function(value) {
            return bcrypt.compareSync(value, this[field]);
        };

        // Add field to schema if not already defined
        if (!schema.path(field)) {
            var pwd = { };
            pwd[field] = { type: String };
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
                encrypt(field, model[field], function(err, hash) {
                    if (err) return next(err);
                    model[field] = hash;
                    if (--count == 0)
                        next();
                });
            });
        } else {
            next();
        }
    });

    function encrypt(field, value, cb) {
        bcrypt.genSalt(schema.path(field).options.rounds || rounds, function(err, salt) {
            if (err) return cb(err);
            bcrypt.hash(value, salt, null, cb);
        });
    }
};
