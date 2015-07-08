var bcrypt = require('bcrypt-nodejs');

module.exports = {
    hash: function(val, salt) {
        return new Promise(function(resolve, reject) {
            bcrypt.hash(val, salt, null, function(err, hash) {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(hash);
                }
            });
        });
    },
    salt: function(rounds) {
        return new Promise(function(resolve, reject) {
            bcrypt.genSalt(rounds || ROUNDS, function(err, salt) {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(salt);
                }
            });
        });
    },
    encrypt: function(val, rounds) {
        var self = this;
        return this.salt(rounds).then(function(salt) {
            return self.hash(val, salt);
        });
    }
};
