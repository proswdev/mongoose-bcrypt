'use strict';

var should = require('should');
var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
var semver = require('semver');
const {mongo} = require("mongoose");

if (semver.gte(mongoose.version, "5.0.7") && semver.lt(mongoose.version, "5.5.3")) {
  mongoose.set('useFindAndModify', false);
}
mongoose.set('strictQuery', false)

function deleteMany(model, cond, opt, cb) {
  if (model.deleteMany) {
    model.deleteMany(cond, opt, cb);
  } else {
    model.remove(cond, opt, cb);
  }
}

describe('mongoose-bcrypt', function() {
  var defaultRounds;

  before(function(done){
    var options;
    if (semver.lt(mongoose.version, "5.0.0")) {
      options = { useMongoClient: true };
    } else {
      options = {};
      if (semver.gte(mongoose.version, "5.2.0")) {
        options.useNewUrlParser = true;
      }
      if (semver.gte(mongoose.version, "5.3.0")) {
        options.useUnifiedTopology = true;
      }
    }
    defaultRounds = bcrypt.getRounds(bcrypt.hashSync('test'));
    mongoose.connect('mongodb://127.0.0.1:27017/test', options, function(err, db) {
      done();
    });
  });

  after(function(done) {
    mongoose.connection.close(done);
  });

  describe('Using default settings', function(){
    var testPwd = 'testPwd';
    var Test1,test1;

    it ('should create document with encrypted field "password"', function(done) {
      var TestSchema1 = new mongoose.Schema({
        name: String
      });
      TestSchema1.plugin(require('../index'));
      (TestSchema1.path('password') == undefined).should.be.false();
      Test1 = mongoose.model('Test1', TestSchema1);
      deleteMany(Test1, function(){
        new Test1({
          name: 'test',
          password: testPwd
        }).save(function(err, test) {
          should.not.exist(err);
          test1 = test;
          done();
        });
      });
    });

    it ('should encrypt password with default rounds', function(done){
      bcrypt.getRounds(test1.password).should.equal(defaultRounds);
      done();
    });

    it ('should return valid encryption value using callback', function(done) {
      Test1.encryptPassword(testPwd, function(err, hash) {
        should.not.exist(err);
        bcrypt.compareSync(testPwd, hash).should.be.true;
        done();
      });
    });

    it ('should return valid encryption value using promise', function() {
      return Test1
        .encryptPassword(testPwd)
        .then(function(hash) {
          bcrypt.compareSync(testPwd, hash).should.be.true;
        })
        .catch(function(err) {
          should.fail(err);
        });
    });

    it ('should accept valid password using callback', function(done) {
      var promise = Promise;
      Promise = null;
      test1.verifyPassword(testPwd, function(err, isMatch){
        should.not.exist(err);
        isMatch.should.be.true;
        Promise = promise;
        done();
      });
    });

    it ('should accept valid password using promise', function() {
      return test1
        .verifyPassword(testPwd)
        .then(function(isMatch) {
          isMatch.should.be.true;
        })
        .catch(function(err) {
          should.fail(err);
        });
    });

    it ('should reject invalid password using callback', function(done) {
      test1.verifyPassword(testPwd + 'bogus', function(err, isMatch){
        should.not.exist(err);
        isMatch.should.be.false();
        done();
      });
    });

    it ('should reject invalid password using promise', function() {
      return test1
        .verifyPassword(testPwd + 'bogus')
        .then(function(isMatch) {
          isMatch.should.be.false();
        })
        .catch(function(err) {
          should.fail(err);
        });
    });

    it ('should accept valid password (sync)', function(done) {
      test1.verifyPasswordSync(testPwd).should.be.true;
      done();
    });

    it ('should reject invalid password (sync)', function(done) {
      test1.verifyPasswordSync(testPwd + 'bogus').should.be.false();
      done();
    });

    it ('should save instance with unchanged password', function(done) {
      test1.name += "Updated";
      test1.save(done);
    });

    it ('should save instance with cleared pasword', function(done) {
      test1.password = null;
      test1.save(done);
    });
  });

  describe('Encrypting existing fields', function() {
    var testPwds = ['testPwd0', 'testPwd1', 'testPwd2', 'testPwd3'];
    var encrypt = ['encryptPwd0', 'encryptPwd1' ];
    var verify = ['verifyPwd0', 'verifyPwd1'];
    var fields = ['pwd0', 'pwd1'];
    var Test2,test2;

    it ('should create document with fields marked for encryption', function(done) {
      var TestSchema2 = new mongoose.Schema({
        name: String,
        value: Number,
        pwd0: { type: String, bcrypt: true },
        pwd1: { type: String, required: true, rounds: 7},
        pwd2: { type: String, bcrypt: true, select: false },
        pwd3: { type: String }
      });
      TestSchema2.plugin(require('../index'), { fields: 'pwd1' });
      Test2 = mongoose.model('Test2', TestSchema2);
      deleteMany(Test2, function(){
        new Test2({
          name: 'test',
          pwd0: testPwds[0],
          pwd1: testPwds[1],
          pwd2: testPwds[2],
          pwd3: testPwds[3]
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

    it ('should return valid encryption values using callbacks', function(done) {
      var count = fields.length;
      for (var i = 0, len = count; i < len; i++) {
        (function() {
          var pwd = testPwds[i];
          Test2[encrypt[i]](pwd, function(err, hash){
            should.not.exist(err);
            bcrypt.compareSync(pwd,hash).should.be.true();
            if (--count == 0)
              done();
          });
        })();
      }
    });

    it ('should return valid encryption values using promises', function() {
      return Promise.all(fields.map(function(field, index) {
          var pwd = testPwds[index];
          return Test2[encrypt[index]](pwd)
          .then(function(hash) {
            bcrypt.compareSync(pwd,hash).should.be.true();
          });
      }))
      .catch(function(err) {
        should.fail(err);
      });
    });

    it ('should accept valid field values using callbacks', function(done) {
      var count = fields.length;
      for (var i = 0, len = count; i < len; i++) {
        test2[verify[i]](testPwds[i], function(err, isMatch){
          should.not.exist(err);
          isMatch.should.be.true();
          if (--count == 0)
            done();
        });
      }
    });

    it ('should accept valid field values using promises', function() {
      return Promise.all(fields.map(function(field, index) {
        return test2[verify[index]](testPwds[index]);
      })).then(function(results) {
        results.length.should.equal(fields.length);
        results.forEach(function(isMatch) {
          isMatch.should.be.true();
        });
      }).catch(function(err) {
        should.fail(err);
      });
    });

    it ('should reject invalid field values using callbacks', function(done) {
      var count = fields.length;
      for (var i = 0, len = count; i < len; i++) {
        test2[verify[i]](testPwds[i]+'bogus', function(err, isMatch){
          should.not.exist(err);
          isMatch.should.be.false();
          if (--count == 0)
            done();
        });
      }
    });

    it ('should reject invalid field values using promises', function() {
      return Promise.all(fields.map(function(field, index) {
        return test2[verify[index]](testPwds[index]+'bogus');
      })).then(function(results) {
        results.length.should.equal(fields.length);
        results.forEach(function(isMatch) {
          isMatch.should.be.false();
        });
      }).catch(function(err) {
        should.fail(err);
      });
    });

    it ('should accept valid field values (sync)', function(done) {
      for (var i = 0, len = fields.length; i < len; i++) {
        test2[verify[i] + "Sync"](testPwds[i]).should.be.true();
      }
      done();
    });

    it ('should reject invalid field values (sync)', function(done) {
      for (var i = 0, len = fields.length; i < len; i++) {
        test2[verify[i] + "Sync"](testPwds[i]+'bogus').should.be.false();
      }
      done();
    });

    it ('should not encrypt unmarked fields', function(done){
      test2.pwd3.should.equal(testPwds[3]);
      bcrypt.getRounds(test2.pwd3).should.be.NaN;
      (test2.verifyPwd3 == undefined).should.be.true();
      (test2.verifyPwd3Sync == undefined).should.be.true();
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
        (TestSchema3.path(fields[i]) == undefined).should.be.false();
      }
      Test3 = mongoose.model('Test3', TestSchema3);
      deleteMany(Test3, function(){
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
            bcrypt.compareSync(pwd,hash).should.be.true();
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
          (err == null).should.be.true();
          isMatch.should.be.true();
          if (--count == 0)
            done();
        });
      }
    });

    it ('should reject invalid field values (async)', function(done) {
      var count = fields.length;
      for (var i = 0, len = count; i < len; i++) {
        test3[verify[i]](testPwds[i]+'bogus', function(err, isMatch){
          (err == null).should.be.true();
          isMatch.should.be.false();
          if (--count == 0)
            done();
        });
      }
    });

    it ('should accept valid field values (sync)', function(done) {
      for (var i = 0, len = fields.length; i < len; i++) {
        test3[verify[i] + "Sync"](testPwds[i]).should.be.true();
      }
      done();
    });

    it ('should reject invalid field values (sync)', function(done) {
      for (var i = 0, len = fields.length; i < len; i++) {
        test3[verify[i] + "Sync"](testPwds[i]+'bogus').should.be.false();
      }
      done();
    });

  });

  describe('Support nested fields', function(){
    var testPwds = ['testPwd0', 'testPwd1', 'testPwd2'];
    var encrypt = ['encryptNestedPwd0', 'encryptNestedPwd1', 'encryptNestedPwd2'];
    var verify = ['verifyNestedPwd0', 'verifyNestedPwd1', 'verifyNestedPwd2'];
    var fields = ['nested.pwd0', 'nested.pwd1', 'nested.pwd2'];
    var Test4, test4;

    it ("shoud create document with nested fields marked for encryption", function(done){
      var TestSchema4 = new mongoose.Schema({
        nested: {
          pwd0: { type: String, bcrypt: true, rounds: 7 },
          pwd1: { type: String }
        }
      });
      TestSchema4.plugin(require('../index'), { fields: ['nested.pwd1', 'nested.pwd2'], rounds: 8 });
      for (var i = 0, len = fields.length; i < len; i++) {
        (TestSchema4.path(fields[i]) == undefined).should.be.false();
      }
      Test4 = mongoose.model('Test4', TestSchema4);
      deleteMany(Test4, function(){
        new Test4({
          nested: {
            pwd0: testPwds[0],
            pwd1: testPwds[1],
            pwd2: testPwds[2]
          }
        }).save(function(err,test){
          should.not.exist(err);
          test4 = test;
          done();
        });
      });
    });
    it ('should encrypt nested field with correct rounds when specified', function(done){
      bcrypt.getRounds(test4.nested.pwd0).should.equal(7);
      done();
    });
    it ('should encrypt nested fields with default rounds when unspecified', function(done){
      bcrypt.getRounds(test4.nested.pwd1).should.equal(8);
      bcrypt.getRounds(test4.nested.pwd2).should.equal(8);
      done();
    });

    it ('should return valid encryption values', function(done) {
      var count = fields.length;
      for (var i = 0, len = count; i < len; i++) {
        (function() {
          var pwd = testPwds[i];
          Test4[encrypt[i]](pwd, function(err, hash){
            should.not.exist(err);
            bcrypt.compareSync(pwd,hash).should.be.true();
            if (--count == 0)
              done();
          });
        })();
      }
    });

    it ('should accept valid field values (async)', function(done) {
      var count = fields.length;
      for (var i = 0, len = count; i < len; i++) {
        test4[verify[i]](testPwds[i], function(err, isMatch){
          (err == null).should.be.true();
          isMatch.should.be.true();
          if (--count == 0)
            done();
        });
      }
    });

    it ('should reject invalid field values (async)', function(done) {
      var count = fields.length;
      for (var i = 0, len = count; i < len; i++) {
        test4[verify[i]](testPwds[i]+'bogus', function(err, isMatch){
          (err == null).should.be.true();
          isMatch.should.be.false();
          if (--count == 0)
            done();
        });
      }
    });

    it ('should accept valid field values (sync)', function(done) {
      for (var i = 0, len = fields.length; i < len; i++) {
        test4[verify[i] + "Sync"](testPwds[i]).should.be.true();
      }
      done();
    });

    it ('should reject invalid field values (sync)', function(done) {
      for (var i = 0, len = fields.length; i < len; i++) {
        test4[verify[i] + "Sync"](testPwds[i]+'bogus').should.be.false();
      }
      done();
    });
  });

  if (semver.gte(mongoose.version, "4.1.3")) {
    function testUpdates(timestamps) {
      var postfix = timestamps ? 'b' : 'a';
      var title = 'Support update queries';
      if (timestamps) {
        title += ' with timestamps';
      }
      describe(title, function () {
        var testPwd = 'testPwd';
        var Test5, test5;
        var Test6, test6;

        before(function (done) {
          var TestSchema5 = new mongoose.Schema({
            name: String
          }, {
            timestamps: timestamps
          });
          TestSchema5.plugin(require('../index'));
          Test5 = mongoose.model('Test5' + postfix, TestSchema5);
          var TestSchema6 = new mongoose.Schema({
            maindoc: String,
            subdocs: {type: [TestSchema5], default:[]}
          });
          TestSchema6.plugin(require('../index'));
          Test6 = mongoose.model('Test6' + postfix, TestSchema6);
          deleteMany(Test5, function () {
            new Test5({
              name: 'test',
              password: testPwd
            }).save(function (err, test) {
              var subdoc = {
                name: 'subdoc1',
                password: testPwd
              };
              deleteMany(Test6, function() {
                test6 = new Test6({
                  maindoc: 'main',
                });
                test6.subdocs.push(subdoc);
                test6.save(function (err, test) {
                  test6 = test;
                  done();
                });
              });
            });
          })
        });

        if (semver.lt(mongoose.version, "5.0.0")) {

          it('should encrypt password when updating with update', function (done) {
            var updatedPassword = 'testPwd2a';
            Test5.update({}, {password: updatedPassword}, function (err) {
              should.not.exist(err);
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    should.not.exist(err);
                    isMatch.should.be.true();
                    done();
                  });
                })
              })
            });
          });

          it('should encrypt password when updating with update & $set', function (done) {
            var updatedPassword = 'testPwd2b';
            Test5.update({}, {$set: {password: updatedPassword}}, function (err) {
              should.not.exist(err);
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    should.not.exist(err);
                    isMatch.should.be.true();
                    done();
                  });
                })
              })
            });
          });

          it('should encrypt password when promises not available', function (done) {
            var promise = Promise;
            Promise = null;
            var updatedPassword = 'testPwd2c';
            Test5.update({}, {password: updatedPassword}, function (err) {
              should.not.exist(err);
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    should.not.exist(err);
                    isMatch.should.be.true();
                    Promise = promise;
                    done();
                  });
                })
              })
            });
          });

        }

        if (semver.gte(mongoose.version, "4.8.0")) {

          it('should encrypt password when updating with updateOne', function (done) {
            var updatedPassword = 'testPwd2';
            Test5.updateOne({}, {password: updatedPassword}, function (err) {
              should.not.exist(err);
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    should.not.exist(err);
                    isMatch.should.be.true();
                    done();
                  });
                })
              })
            });
          });

          it('should encrypt password when updating with updateOne & $set', function (done) {
            var updatedPassword = 'testPwd2';
            Test5.updateOne({}, {$set: {password: updatedPassword}}, function (err) {
              should.not.exist(err);
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    should.not.exist(err);
                    isMatch.should.be.true();
                    done();
                  });
                })
              })
            });
          });

          it('should encrypt password when promises not available', function (done) {
            var promise = Promise;
            Promise = null;
            var updatedPassword = 'testPwd2c';
            Test5.updateOne({}, {password: updatedPassword}, function (err) {
              should.not.exist(err);
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    should.not.exist(err);
                    isMatch.should.be.true();
                    Promise = promise;
                    done();
                  });
                })
              })
            });
          });

          it('should encrypt password when updating with updateMany', function (done) {
            var updatedPassword = 'testPwd2';
            Test5.updateMany({}, {password: updatedPassword}, function (err) {
              should.not.exist(err);
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    should.not.exist(err);
                    isMatch.should.be.true();
                    done();
                  });
                })
              })
            });
          });

          it('should encrypt password when updating with updateMany & $set', function (done) {
            var updatedPassword = 'testPwd2';
            Test5.updateMany({}, {$set: {password: updatedPassword}}, function (err) {
              should.not.exist(err);
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    should.not.exist(err);
                    isMatch.should.be.true();
                    done();
                  });
                })
              })
            });
          });
        }

        it('should encrypt password when find and updating', function (done) {
          var updatedPassword = 'testPwd2';
          Test5.findOneAndUpdate({name: 'test'}, {password: updatedPassword}, function (err) {
            should.not.exist(err);
            Test5.find({}, function (err, results) {
              results.forEach(function (test) {
                test.verifyPassword(updatedPassword, function (err, isMatch) {
                  should.not.exist(err);
                  isMatch.should.be.true();
                  done();
                });
              })
            })
          });
        });

        it('should clear hash when find and updating with empty password ', function (done) {
          var updatedPassword = null;
          Test5.findOneAndUpdate({name: 'test'}, {password: updatedPassword}, function (err) {
            should.not.exist(err);
            Test5.find({}, function (err, results) {
              results.forEach(function (test) {
                test.password.should.be.empty();
                done();
              });
            });
          });
        });

        it('should encrypt password when find and updating using $set', function (done) {
          var updatedPassword = 'testPwd2';
          Test5.findOneAndUpdate({name: 'test'}, {$set: {password: updatedPassword}}, function (err) {
            should.not.exist(err);
            Test5.find({}, function (err, results) {
              results.forEach(function (test) {
                test.verifyPassword(updatedPassword, function (err, isMatch) {
                  should.not.exist(err);
                  isMatch.should.be.true();
                  done();
                });
              })
            })
          });
        });

        it('should clear hash when find and updating using $set with empty password ', function (done) {
          var updatedPassword = null;
          Test5.findOneAndUpdate({name: 'test'}, {$set: {password: updatedPassword}}, function (err) {
            should.not.exist(err);
            Test5.find({}, function (err, results) {
              results.forEach(function (test) {
                test.password.should.be.empty();
                done();
              });
            });
          });
        });

        // it('should encrypt password in subdocs when find and updating', function (done) {
        //   test6.subdocs[0].verifyPasswordSync(testPwd).should.be.true();
        //   var newPassword = 'testPwd2';
        //   var newSubdoc = new Test5({ name: 'newSubdoc', password: newPassword}, );
        //   Test6.findOneAndUpdate({_id: test6._id}, {$push: {subdocs: newSubdoc}}, {new: true}, function(err) {
        //     should.not.exist(err);
        //     Test6.find({}, function(err, results) {
        //       results.forEach(function (test) {
        //         test.subdocs.length.should.equal(2);
        //         test.subdocs[0].verifyPasswordSync(testPwd).should.be.true();
        //         test.subdocs[1].verifyPasswordSync(newPassword).should.be.true();
        //         done();
        //       })
        //     })
        //   })
        // });

      });
    }
    testUpdates(false);
    testUpdates(true);
  }
});
