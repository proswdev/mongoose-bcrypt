'use strict';

var should = require('should');
var mongoose = require('mongoose');
var bcrypt = require('bcrypt-nodejs');

describe('mongoose-bcrypt', function() {
    var defaultRounds;

    before(function(done){
        mongoose.connect('mongodb://localhost:27017/test');
        defaultRounds = bcrypt.getRounds(bcrypt.hashSync('test'));
        done();
    });

    describe('Using default settings', function(){
        var testPwd = 'testPwd';
        var Test1,test1;

        it ('should create document with encrypted field "password"', function(done) {
            var TestSchema1 = new mongoose.Schema({
                name: String
            });
            TestSchema1.plugin(require('../index'));
            (TestSchema1.path('password') == undefined).should.be.false;
            Test1 = mongoose.model('Test1', TestSchema1);
            Test1.remove(function(){
                new Test1({
                    name: 'test',
                    password: testPwd
                }).save(function(err, test) {
                    should.not.exist(err);
                    test1 = test;
                    done();
                });
            })
        });

        it ('should encrypt password with default rounds', function(done){
            bcrypt.getRounds(test1.password).should.equal(defaultRounds);
            done();
        });

        it ('should return valid encryption value', function(done) {
            Test1.encryptPassword(testPwd, function(err, hash) {
                should.not.exist(err);
                bcrypt.compareSync(testPwd, hash).should.be.true;
                done();
            });
        });

        it ('should accept valid password (async)', function(done) {
            test1.verifyPassword(testPwd, function(err, isMatch){
                should.not.exist(err);
                isMatch.should.be.true;
                done();
            });
        });

        it ('should reject invalid password (async)', function(done) {
            test1.verifyPassword(testPwd + 'bogus', function(err, isMatch){
                should.not.exist(err);
                isMatch.should.be.false;
                done();
            });
        });

        it ('should accept valid password (sync)', function(done) {
            test1.verifyPasswordSync(testPwd).should.be.true;
            done();
        });

        it ('should reject invalid password (sync)', function(done) {
            test1.verifyPasswordSync(testPwd + 'bogus').should.be.false;
            done();
        });

        it ('should save instance with unchanged password', function(done) {
            test1.name += "Updated";
            test1.save(done);
        });
    });

    describe('Encrypting existing fields', function() {
        var testPwds = ['testPwd0', 'testPwd1', 'testPwd2'];
        var encrypt = ['encryptPwd0', 'encryptPwd1' ];
        var verify = ['verifyPwd0', 'verifyPwd1'];
        var fields = ['pwd0', 'pwd1'];
        var Test2,test2;

        it ('should create document with fields marked for encryption', function(done) {
            var TestSchema2 = new mongoose.Schema({
                name: String,
                value: Number,
                pwd0: { type: String, bcrypt: true },
                pwd1: { type: String, required: true, bcrypt: true, rounds: 7},
                pwd2: { type: String }
            });
            TestSchema2.plugin(require('../index'));
            Test2 = mongoose.model('Test2', TestSchema2);
            Test2.remove(function(){
                new Test2({
                    name: 'test',
                    pwd0: testPwds[0],
                    pwd1: testPwds[1],
                    pwd2: testPwds[2]
                }).save(function(err,test){
                    should.not.exist(err);
                    test2 = test;
                    done();
                })
            });
        });

        it ('should encrypt fields with default rounds when unspecified', function(done){
            bcrypt.getRounds(test2.pwd0).should.equal(defaultRounds);
            done();
        });

        it ('should encrypt field with correct rounds when specified', function(done){
            bcrypt.getRounds(test2.pwd1).should.equal(7);
            done();
        });

        it ('should return valid encryption values', function(done) {
            var count = fields.length;
            for (var i = 0, len = count; i < len; i++) {
                (function() {
                    var pwd = testPwds[i];
                    Test2[encrypt[i]](pwd, function(err, hash){
                        should.not.exist(err);
                        bcrypt.compareSync(pwd,hash).should.be.true;
                        if (--count == 0)
                            done();
                    });
                })();
            }
        });

        it ('should accept valid field values (async)', function(done) {
            var count = fields.length;
            for (var i = 0, len = count; i < len; i++) {
                test2[verify[i]](testPwds[i], function(err, isMatch){
                    should.not.exist(err);
                    isMatch.should.be.true;
                    if (--count == 0)
                        done();
                });
            }
        });

        it ('should reject invalid field values (async)', function(done) {
            var count = fields.length;
            for (var i = 0, len = count; i < len; i++) {
                test2[verify[i]](testPwds[i]+'bogus', function(err, isMatch){
                    should.not.exist(err);
                    isMatch.should.be.false;
                    if (--count == 0)
                        done();
                });
            }
        });

        it ('should accept valid field values (sync)', function(done) {
            for (var i = 0, len = fields.length; i < len; i++) {
                test2[verify[i] + "Sync"](testPwds[i]).should.be.true;
            }
            done();
        });

        it ('should reject invalid field values (sync)', function(done) {
            for (var i = 0, len = fields.length; i < len; i++) {
                test2[verify[i] + "Sync"](testPwds[i]+'bogus').should.be.false;
            }
            done();
        });

        it ('should not encrypt unmarked fields', function(done){
            test2.pwd2.should.equal(testPwds[2]);
            bcrypt.getRounds(test2.pwd2).should.be.NaN;
            (test2.verifyPwd2 == undefined).should.be.true;
            (test2.verifyPwd2Sync == undefined).should.be.true;
            done();
        });

    });

    describe('Encrypting both new and existing fields', function(){
        var testPwds = ['testPwd0', 'testPwd1', 'testPwd2', 'testPwd3'];
        var encrypt = ['encryptPwd0', 'encryptPwd1', 'encryptPwd2', 'encryptPwd3'];
        var verify = ['verifyPwd0', 'verifyPwd1', 'verifyPwd2', 'verifyPwd3'];
        var fields = ['pwd0', 'pwd1', 'pwd2', 'pwd3'];
        var Test3,test3;

        it ('should create document with multiple encrypted fields added', function(done) {
            var TestSchema3 = new mongoose.Schema({
                name: String,
                pwd1: { type: String, required: true, rounds: 7 },
                pwd3: { type: String, bcrypt: true }
            });
            TestSchema3.plugin(require('../index'), { fields: ['pwd0', 'pwd1', 'pwd2'], rounds: 8 });
            for (var i = 0, len = fields.length; i < len; i++) {
                (TestSchema3.path(fields[i]) == undefined).should.be.false;
            }
            Test3 = mongoose.model('Test3', TestSchema3);
            Test3.remove(function(){
                new Test3({
                    name: 'test',
                    pwd0: testPwds[0],
                    pwd1: testPwds[1],
                    pwd2: testPwds[2],
                    pwd3: testPwds[3]
                }).save(function(err,test){
                    should.not.exist(err);
                    test3 = test;
                    done();
                });
            });
        });

        it ('should encrypt field with correct rounds when specified', function(done){
            bcrypt.getRounds(test3.pwd1).should.equal(7);
            done();
        });

        it ('should encrypt fields with default rounds when unspecified', function(done){
            bcrypt.getRounds(test3.pwd0).should.equal(8);
            bcrypt.getRounds(test3.pwd2).should.equal(8);
            bcrypt.getRounds(test3.pwd3).should.equal(8);
            done();
        });

        it ('should return valid encryption values', function(done) {
            var count = fields.length;
            for (var i = 0, len = count; i < len; i++) {
                (function() {
                    var pwd = testPwds[i];
                    Test3[encrypt[i]](pwd, function(err, hash){
                        should.not.exist(err);
                        bcrypt.compareSync(pwd,hash).should.be.true;
                        if (--count == 0)
                            done();
                    });
                })();
            }
        });

        it ('should accept valid field values (async)', function(done) {
            var count = fields.length;
            for (var i = 0, len = count; i < len; i++) {
                test3[verify[i]](testPwds[i], function(err, isMatch){
                    (err == null).should.be.true;
                    isMatch.should.be.true;
                    if (--count == 0)
                        done();
                });
            }
        });

        it ('should reject invalid field values (async)', function(done) {
            var count = fields.length;
            for (var i = 0, len = count; i < len; i++) {
                test3[verify[i]](testPwds[i]+'bogus', function(err, isMatch){
                    (err == null).should.be.true;
                    isMatch.should.be.false;
                    if (--count == 0)
                        done();
                });
            }
        });

        it ('should accept valid field values (sync)', function(done) {
            for (var i = 0, len = fields.length; i < len; i++) {
                test3[verify[i] + "Sync"](testPwds[i]).should.be.true;
            }
            done();
        });

        it ('should reject invalid field values (sync)', function(done) {
            for (var i = 0, len = fields.length; i < len; i++) {
                test3[verify[i] + "Sync"](testPwds[i]+'bogus').should.be.false;
            }
            done();
        });

    });

});
