'use strict';

var should = require('should');
var mongoose = require('mongoose');
var bcrypt = require('bcrypt-nodejs');

describe('mongoose-bcrypt', function() {
    var testConn;
    var defaultRounds;

    before(function(done){
        testConn = mongoose.createConnection('mongodb://localhost:27017/test');
        defaultRounds = bcrypt.getRounds(bcrypt.hashSync('test'));
        done();
    });

    describe('Using default settings', function(){
        var testPwd = 'testPwd';
        var test1;

        it ('should create document with encrypted field "password"', function(done) {
            var TestSchema1 = new mongoose.Schema({
                name: String
            });
            TestSchema1.plugin(require('../index'));
            (TestSchema1.path('password') == undefined).should.be.false;
            var Test1 = testConn.model('Test1', TestSchema1);
            Test1.remove(function(){
                test1 = new Test1({
                    name: 'test',
                    password: testPwd
                });
                test1.save(done);
            })
        });

        it ('should encrypt password with default rounds', function(done){
            bcrypt.getRounds(test1.password).should.equal(defaultRounds);
            done();
        });

        it ('should accept valid password (async)', function(done) {
            test1.verifyPassword(testPwd, function(err, isMatch){
                (err == null).should.be.true;
                isMatch.should.be.true;
                done();
            });
        });

        it ('should reject invalid password (async)', function(done) {
            test1.verifyPassword(testPwd + 'bogus', function(err, isMatch){
                (err == null).should.be.true;
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

        it ('should save instance with unchaged password', function(done) {
            test1.name += "Updated";
            test1.save(done);
        });
    });

    describe('Using multiple fields', function(){
        var testPwds = ['testPwd0', 'testPwd1', 'testPwd2'];
        var verify = ['verifyPwd0', 'verifyPwd1', 'verifyPwd2'];
        var fields = ['pwd0', 'pwd1', 'pwd2'];
        var test2;

        it ('should create document with multiple encrypted fields', function(done) {
            var TestSchema2 = new mongoose.Schema({
                name: String,
                pwd1: { type: String, required: true, rounds: 7}
            });
            TestSchema2.plugin(require('../index'), { fields: fields, rounds: 8 });
            for (var i = 0, len = fields.length; i < len; i++) {
                (TestSchema2.path(fields[i]) == undefined).should.be.false;
            }
            var Test = testConn.model('Test2', TestSchema2);
            Test.remove(function(){
                test2 = new Test({
                    name: 'test',
                    pwd0: testPwds[0],
                    pwd1: testPwds[1],
                    pwd2: testPwds[2]
                });
                test2.save(done);
            });
        });

        it ('should encrypt field with correct rounds when specified', function(done){
            bcrypt.getRounds(test2.pwd1).should.equal(7);
            done();
        });

        it ('should encrypt fields with default rounds when unspecified', function(done){
            bcrypt.getRounds(test2.pwd0).should.equal(8);
            bcrypt.getRounds(test2.pwd2).should.equal(8);
            done();
        });

        it ('should accept valid field values (async)', function(done) {
            var count = fields.length;
            for (var i = 0, len = count; i < len; i++) {
                test2[verify[i]](testPwds[i], function(err, isMatch){
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
                test2[verify[i]](testPwds[i]+'bogus', function(err, isMatch){
                    (err == null).should.be.true;
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

    });

});
