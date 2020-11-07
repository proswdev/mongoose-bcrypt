'use strict';

var mongoose = require('mongoose');
var bcrypt = require('bcryptjs');
var semver = require('semver');
mongoose.Promise = global.Promise = require('bluebird');
mongoose.set('useFindAndModify', false);

function deleteMany(model, cond, opt, cb) {
  if (model.deleteMany) {
    model.deleteMany(cond, opt, cb);
  } else {
    model.remove(cond, opt, cb);
  }
}

function createDocumentWithNewModel(model, objects, testDocuments, done) {
  new model(objects[0]).save(function (err, testDoc) {
    expect(err).toBeNull();
    testDocuments.push(testDoc);
    done();
  });
}

function createDocumentsWithInsertMany(model, objects, testDocuments, done) {
  model.insertMany(objects, function (err, testDocs) {
    expect(err).toBeNull();
    testDocs.forEach(function (doc) {
      testDocuments.push(doc);
    });
    done();
  });
}

describe('mongoose-bcrypt', function () {
  var defaultRounds;
  var describeSuites;
  var test1, test2, test3, test4, testPwd, testPwds;

  beforeAll(function (done) {
    var options;
    if (semver.lt(mongoose.version, '5.0.0')) {
      options = { useMongoClient: true };
    } else {
      options = {};
      if (semver.gte(mongoose.version, '5.2.0')) {
        options.useNewUrlParser = true;
      }
      if (semver.gte(mongoose.version, '5.3.0')) {
        options.useUnifiedTopology = true;
      }
    }
    defaultRounds = bcrypt.getRounds(bcrypt.hashSync('test'));
    mongoose.connect('mongodb://127.0.0.1:27017/test', options, function (
      err,
      db
    ) {
      done();
    });
  });

  afterAll(function (done) {
    mongoose.connection.close(done);
  });

  testPwd = 'testPwd';
  testPwds = ['testPwd0', 'testPwd1', 'testPwd2', 'testPwd3'];

  test1 = {
    name: 'test',
    password: testPwd,
    index: 0,
  };

  test2 = {
    name: 'test',
    pwd0: testPwds[0],
    pwd1: testPwds[1],
    pwd2: testPwds[2],
    pwd3: testPwds[3],
    index: 0,
  };

  test3 = Object.assign({}, test2);

  test4 = {
    nested: {
      pwd0: testPwds[0],
      pwd1: testPwds[1],
      pwd2: testPwds[2],
    },
    index: 0,
  };

  describeSuites = [
    [
      'create document with "new Model"',
      createDocumentWithNewModel,
      [[test1], [test2], [test3], [test4]],
    ],
    [
      'create documents with "Model.insertMany"',
      createDocumentsWithInsertMany,
      [
        [
          Object.assign({}, test1, { name: 'test11', index: 0 }),
          Object.assign({}, test1, { name: 'test12', index: 1 }),
        ],
        [
          Object.assign({}, test2, { name: 'test21', index: 0 }),
          Object.assign({}, test2, { name: 'test22', index: 1 }),
        ],
        [
          Object.assign({}, test3, { name: 'test31', index: 0 }),
          Object.assign({}, test3, { name: 'test32', index: 1 }),
        ],
        [
          Object.assign({}, test4, { index: 0 }),
          Object.assign({}, test4, { index: 1 }),
        ],
      ],
    ],
  ];

  describe.each(describeSuites)('%s', function (_, creatingFunction, testData) {
    describe('Using default settings', function () {
      var Test1,
        testDocuments1 = [];

      beforeAll(function (done) {
        var TestSchema1 = new mongoose.Schema({
          name: String,
        });
        TestSchema1.plugin(require('../index'));
        expect(TestSchema1.path('password')).toBeDefined();
        Test1 = mongoose.model('Test1', TestSchema1);
        deleteMany(Test1, function () {
          creatingFunction(Test1, testData[0], testDocuments1, done);
        });
      });

      afterAll(function (done) {
        mongoose.deleteModel('Test1');
        done();
      });

      it('should create documents with encrypted field "password"', function () {
        expect(testDocuments1.length).toBe(testData[0].length);
      });

      it('should return valid encryption value using callback', function (done) {
        Test1.encryptPassword(testPwd, function (err, hash) {
          expect(err).toBeNull();
          expect(bcrypt.compareSync(testPwd, hash)).toBe(true);
          done();
        });
      });

      it('should return valid encryption value using promise', function () {
        return Test1.encryptPassword(testPwd)
          .then(function (hash) {
            expect(bcrypt.compareSync(testPwd, hash)).toBe(true);
          })
          .catch(function (err) {
            expect(err).toBeNull();
          });
      });

      describe.each(testData[0])('test document1.%#', function (
        originalTestDocument
      ) {
        var testDocument1;

        beforeAll(() => {
          testDocument1 = testDocuments1[originalTestDocument.index];
        });

        it(`should encrypt password with default rounds in the document `, function (done) {
          expect(bcrypt.getRounds(testDocument1.password)).toEqual(
            defaultRounds
          );
          done();
        });

        it(`should accept valid password using callback in the document `, function (done) {
          var promise = Promise;
          Promise = null;
          testDocument1.verifyPassword(testPwd, function (err, isMatch) {
            expect(err).toBeNull();
            expect(isMatch).toBe(true);
            Promise = promise;
            done();
          });
        });

        it(`should accept valid password using promise in the document `, function () {
          return testDocument1
            .verifyPassword(testPwd)
            .then(function (isMatch) {
              expect(isMatch).toBe(true);
            })
            .catch(function (err) {
              expect(err).toBeNull();
            });
        });

        it(`should reject invalid password using callback in the document `, function (done) {
          testDocument1.verifyPassword(testPwd + 'bogus', function (
            err,
            isMatch
          ) {
            expect(err).toBeNull();
            expect(isMatch).toBe(false);
            done();
          });
        });

        it(`should reject invalid password using promise in the document `, function () {
          return testDocument1
            .verifyPassword(testPwd + 'bogus')
            .then(function (isMatch) {
              expect(isMatch).toBe(false);
            })
            .catch(function (err) {
              expect(err).toBeNull();
            });
        });

        it(`should accept valid password (sync) in the document `, function (done) {
          expect(testDocument1.verifyPasswordSync(testPwd)).toBe(true);
          done();
        });

        it(`should reject invalid password (sync) in the document `, function (done) {
          expect(testDocument1.verifyPasswordSync(testPwd + 'bogus')).toBe(
            false
          );
          done();
        });

        it(`should save instance with unchanged password in the document `, function (done) {
          testDocument1.name += 'Updated';
          testDocument1.save(done);
        });

        it(`should save instance with cleared pasword in the document `, function (done) {
          testDocument1.password = null;
          testDocument1.save(done);
        });
      });
    });

    describe('Encrypting existing fields', function () {
      var encrypt = ['encryptPwd0', 'encryptPwd1'];
      var verify = ['verifyPwd0', 'verifyPwd1'];
      var fields = ['pwd0', 'pwd1'];
      var Test2,
        testDocuments2 = [];

      beforeAll(function (done) {
        var TestSchema2 = new mongoose.Schema({
          name: String,
          value: Number,
          pwd0: { type: String, bcrypt: true },
          pwd1: { type: String, required: true, rounds: 7 },
          pwd2: { type: String, bcrypt: true, select: false },
          pwd3: { type: String },
        });
        TestSchema2.plugin(require('../index'), { fields: 'pwd1' });
        Test2 = mongoose.model('Test2', TestSchema2);
        deleteMany(Test2, function () {
          creatingFunction(Test2, testData[1], testDocuments2, done);
        });
      });

      afterAll(function (done) {
        mongoose.deleteModel('Test2');
        done();
      });

      it('should create documents with fields marked for encryption', function () {
        expect(testDocuments2.length).toBe(testData[1].length);
      });

      it('should return valid encryption values using callbacks', function (done) {
        var count = fields.length;
        for (var i = 0, len = count; i < len; i++) {
          (function () {
            var pwd = testPwds[i];
            Test2[encrypt[i]](pwd, function (err, hash) {
              expect(err).toBeNull();
              expect(bcrypt.compareSync(pwd, hash)).toBe(true);
              if (--count == 0) done();
            });
          })();
        }
      });

      it('should return valid encryption values using promises', function () {
        return Promise.map(fields, function (field, index) {
          var pwd = testPwds[index];
          return Test2[encrypt[index]](pwd).then(function (hash) {
            expect(bcrypt.compareSync(pwd, hash)).toBe(true);
          });
        }).catch(function (err) {
          expect(err).toBeNull();
        });
      });

      describe.each(testData[1])('test document2.%#', function (
        originalTestDocument
      ) {
        var testDocument2;

        beforeAll(() => {
          testDocument2 = testDocuments2[originalTestDocument.index];
        });

        it(`should encrypt fields with default rounds when unspecified in the document`, function (done) {
          expect(bcrypt.getRounds(testDocument2.pwd0)).toEqual(defaultRounds);
          done();
        });

        it(`should encrypt field with correct rounds when specified in the document`, function (done) {
          expect(bcrypt.getRounds(testDocument2.pwd1)).toEqual(7);
          done();
        });

        it(`should accept valid field values using callbacks in the document`, function (done) {
          var count = fields.length;
          for (var i = 0, len = count; i < len; i++) {
            testDocument2[verify[i]](testPwds[i], function (err, isMatch) {
              expect(err).toBeNull();
              expect(isMatch).toBe(true);
              if (--count == 0) done();
            });
          }
        });

        it(`should accept valid field values using promises in the document`, function () {
          return Promise.map(fields, function (_, index) {
            return testDocument2[verify[index]](testPwds[index]);
          })
            .then(function (results) {
              expect(results.length).toEqual(fields.length);
              results.forEach(function (isMatch) {
                expect(isMatch).toBe(true);
              });
            })
            .catch(function (err) {
              expect(err).toBeNull();
            });
        });

        it(`should reject invalid field values using callbacks in the document`, function (done) {
          var count = fields.length;
          for (var i = 0, len = count; i < len; i++) {
            testDocument2[verify[i]](testPwds[i] + 'bogus', function (
              err,
              isMatch
            ) {
              expect(err).toBeNull();
              expect(isMatch).toBe(false);
              if (--count == 0) done();
            });
          }
        });

        it(`should reject invalid field values using promises in the document`, function () {
          return Promise.map(fields, function (_, index) {
            return testDocument2[verify[index]](testPwds[index] + 'bogus');
          })
            .then(function (results) {
              expect(results.length).toEqual(fields.length);
              results.forEach(function (isMatch) {
                expect(isMatch).toBe(false);
              });
            })
            .catch(function (err) {
              expect(err).toBeNull();
            });
        });

        it(`should accept valid field values (sync) in the document`, function (done) {
          for (var i = 0, len = fields.length; i < len; i++) {
            expect(testDocument2[verify[i] + 'Sync'](testPwds[i])).toBe(true);
          }
          done();
        });

        it(`should reject invalid field values (sync) in the document`, function (done) {
          for (var i = 0, len = fields.length; i < len; i++) {
            expect(
              testDocument2[verify[i] + 'Sync'](testPwds[i] + 'bogus')
            ).toBe(false);
          }
          done();
        });

        it(`should not encrypt unmarked fields in the document`, function (done) {
          expect(testDocument2.pwd3).toEqual(testPwds[3]);
          expect(bcrypt.getRounds(testDocument2.pwd3)).toBeNaN();
          expect(testDocument2.verifyPwd3).toBeUndefined();
          expect(testDocument2.verifyPwd3Sync).toBeUndefined();
          done();
        });
      });
    });

    describe('Encrypting both new and existing fields', function () {
      var encrypt = [
        'encryptPwd0',
        'encryptPwd1',
        'encryptPwd2',
        'encryptPwd3',
      ];
      var verify = ['verifyPwd0', 'verifyPwd1', 'verifyPwd2', 'verifyPwd3'];
      var fields = ['pwd0', 'pwd1', 'pwd2', 'pwd3'];
      var Test3,
        testDocuments3 = [];

      beforeAll(function (done) {
        var TestSchema3 = new mongoose.Schema({
          name: String,
          pwd1: { type: String, required: true, rounds: 7 },
          pwd3: { type: String, bcrypt: true },
        });
        TestSchema3.plugin(require('../index'), {
          fields: ['pwd0', 'pwd1', 'pwd2'],
          rounds: 8,
        });
        for (var i = 0, len = fields.length; i < len; i++) {
          expect(TestSchema3.path(fields[i])).toBeDefined();
        }
        Test3 = mongoose.model('Test3', TestSchema3);
        deleteMany(Test3, function () {
          creatingFunction(Test3, testData[2], testDocuments3, done);
        });
      });

      afterAll(function (done) {
        mongoose.deleteModel('Test3');
        done();
      });

      it('should create document with multiple encrypted fields added', function () {
        expect(testDocuments3.length).toBe(testData[2].length);
      });

      it('should return valid encryption values', function (done) {
        var count = fields.length;
        for (var i = 0, len = count; i < len; i++) {
          (function () {
            var pwd = testPwds[i];
            Test3[encrypt[i]](pwd, function (err, hash) {
              expect(err).toBeNull();
              expect(bcrypt.compareSync(pwd, hash)).toBe(true);
              if (--count == 0) done();
            });
          })();
        }
      });

      describe.each(testData[2])('test document3.%#', function (
        originalTestDocument
      ) {
        var testDocument3;

        beforeAll(() => {
          testDocument3 = testDocuments3[originalTestDocument.index];
        });

        it(`should encrypt field with correct rounds when specified in the document`, function (done) {
          expect(bcrypt.getRounds(testDocument3.pwd1)).toEqual(7);
          done();
        });

        it(`should encrypt fields with default rounds when unspecified in the document`, function (done) {
          expect(bcrypt.getRounds(testDocument3.pwd0)).toEqual(8);
          expect(bcrypt.getRounds(testDocument3.pwd2)).toEqual(8);
          expect(bcrypt.getRounds(testDocument3.pwd3)).toEqual(8);
          done();
        });

        it(`should accept valid field values (async) in the document`, function (done) {
          var count = fields.length;
          for (var i = 0, len = count; i < len; i++) {
            testDocument3[verify[i]](testPwds[i], function (err, isMatch) {
              expect(err).toBeNull();
              expect(isMatch).toBe(true);
              if (--count == 0) done();
            });
          }
        });

        it(`should reject invalid field values (async) in the document`, function (done) {
          var count = fields.length;
          for (var i = 0, len = count; i < len; i++) {
            testDocument3[verify[i]](testPwds[i] + 'bogus', function (
              err,
              isMatch
            ) {
              expect(err).toBeNull();
              expect(isMatch).toBe(false);
              if (--count == 0) done();
            });
          }
        });

        it(`should accept valid field values (sync) in the document`, function (done) {
          for (var i = 0, len = fields.length; i < len; i++) {
            expect(testDocument3[verify[i] + 'Sync'](testPwds[i])).toBe(true);
          }
          done();
        });

        it(`should reject invalid field values (sync) in the document`, function (done) {
          for (var i = 0, len = fields.length; i < len; i++) {
            expect(
              testDocument3[verify[i] + 'Sync'](testPwds[i] + 'bogus')
            ).toBe(false);
          }
          done();
        });
      });
    });

    describe('Support nested fields', function () {
      var encrypt = [
        'encryptNestedPwd0',
        'encryptNestedPwd1',
        'encryptNestedPwd2',
      ];
      var verify = ['verifyNestedPwd0', 'verifyNestedPwd1', 'verifyNestedPwd2'];
      var fields = ['nested.pwd0', 'nested.pwd1', 'nested.pwd2'];
      var Test4,
        testDocuments4 = [];

      beforeAll(function (done) {
        var TestSchema4 = new mongoose.Schema({
          nested: {
            pwd0: { type: String, bcrypt: true, rounds: 7 },
            pwd1: { type: String },
          },
        });
        TestSchema4.plugin(require('../index'), {
          fields: ['nested.pwd1', 'nested.pwd2'],
          rounds: 8,
        });
        for (var i = 0, len = fields.length; i < len; i++) {
          expect(TestSchema4.path(fields[i])).toBeDefined();
        }
        Test4 = mongoose.model('Test4', TestSchema4);
        deleteMany(Test4, function () {
          creatingFunction(Test4, testData[3], testDocuments4, done);
        });
      });

      afterAll(function (done) {
        mongoose.deleteModel('Test4');
        done();
      });

      it('shoud create document with nested fields marked for encryption', function () {
        expect(testDocuments4.length).toBe(testData[3].length);
      });

      it('should return valid encryption values', function (done) {
        var count = fields.length;
        for (var i = 0, len = count; i < len; i++) {
          (function () {
            var pwd = testPwds[i];
            Test4[encrypt[i]](pwd, function (err, hash) {
              expect(err).toBeNull();
              expect(bcrypt.compareSync(pwd, hash)).toBe(true);
              if (--count == 0) done();
            });
          })();
        }
      });

      describe.each(testData[3])('test document4.%#', function (
        originalTestDocument
      ) {
        var testDocument4;

        beforeAll(() => {
          testDocument4 = testDocuments4[originalTestDocument.index];
        });

        it(`should encrypt nested field with correct rounds when specified in the document`, function (done) {
          expect(bcrypt.getRounds(testDocument4.nested.pwd0)).toEqual(7);
          done();
        });

        it(`should encrypt nested fields with default rounds when unspecified in the document`, function (done) {
          expect(bcrypt.getRounds(testDocument4.nested.pwd1)).toEqual(8);
          expect(bcrypt.getRounds(testDocument4.nested.pwd2)).toEqual(8);
          done();
        });

        it(`should accept valid field values (async) in the document`, function (done) {
          var count = fields.length;
          for (var i = 0, len = count; i < len; i++) {
            testDocument4[verify[i]](testPwds[i], function (err, isMatch) {
              expect(err).toBeNull();
              expect(isMatch).toBe(true);
              if (--count == 0) done();
            });
          }
        });

        it(`should reject invalid field values (async) in the document`, function (done) {
          var count = fields.length;
          for (var i = 0, len = count; i < len; i++) {
            testDocument4[verify[i]](testPwds[i] + 'bogus', function (
              err,
              isMatch
            ) {
              expect(err).toBeNull();
              expect(isMatch).toBe(false);
              if (--count == 0) done();
            });
          }
        });

        it(`should accept valid field values (sync) in the document`, function (done) {
          for (var i = 0, len = fields.length; i < len; i++) {
            expect(testDocument4[verify[i] + 'Sync'](testPwds[i])).toBe(true);
          }
          done();
        });

        it(`should reject invalid field values (sync) in the document`, function (done) {
          for (var i = 0, len = fields.length; i < len; i++) {
            expect(
              testDocument4[verify[i] + 'Sync'](testPwds[i] + 'bogus')
            ).toBe(false);
          }
          done();
        });
      });
    });
  });

  if (semver.gte(mongoose.version, '4.1.3')) {
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

        beforeAll(function (done) {
          var TestSchema5 = new mongoose.Schema(
            {
              name: String,
            },
            {
              timestamps: timestamps,
            }
          );
          TestSchema5.plugin(require('../index'));
          Test5 = mongoose.model('Test5' + postfix, TestSchema5);
          var TestSchema6 = new mongoose.Schema({
            maindoc: String,
            subdocs: { type: [TestSchema5], default: [] },
          });
          TestSchema6.plugin(require('../index'));
          Test6 = mongoose.model('Test6' + postfix, TestSchema6);
          deleteMany(Test5, function () {
            new Test5({
              name: 'test',
              password: testPwd,
            }).save(function (err, test) {
              var subdoc = {
                name: 'subdoc1',
                password: testPwd,
              };
              deleteMany(Test6, function () {
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
          });
        });

        if (semver.lt(mongoose.version, '5.0.0')) {
          it('should encrypt password when updating with update', function (done) {
            var updatedPassword = 'testPwd2a';
            Test5.update({}, { password: updatedPassword }, function (err) {
              expect(err).toBeNull();
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    expect(err).toBeNull();
                    expect(isMatch).toBe(true);
                    done();
                  });
                });
              });
            });
          });

          it('should encrypt password when updating with update & $set', function (done) {
            var updatedPassword = 'testPwd2b';
            Test5.update({}, { $set: { password: updatedPassword } }, function (
              err
            ) {
              expect(err).toBeNull();
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    expect(err).toBeNull();
                    expect(isMatch).toBe(true);
                    done();
                  });
                });
              });
            });
          });

          it('should encrypt password when promises not available', function (done) {
            var promise = Promise;
            Promise = null;
            var updatedPassword = 'testPwd2c';
            Test5.update({}, { password: updatedPassword }, function (err) {
              expect(err).toBeNull();
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    expect(err).toBeNull();
                    expect(isMatch).toBe(true);
                    Promise = promise;
                    done();
                  });
                });
              });
            });
          });
        }

        if (semver.gte(mongoose.version, '4.8.0')) {
          it('should encrypt password when updating with updateOne', function (done) {
            var updatedPassword = 'testPwd2';
            Test5.updateOne({}, { password: updatedPassword }, function (err) {
              expect(err).toBeNull();
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    expect(err).toBeNull();
                    expect(isMatch).toBe(true);
                    done();
                  });
                });
              });
            });
          });

          it('should encrypt password when updating with updateOne & $set', function (done) {
            var updatedPassword = 'testPwd2';
            Test5.updateOne(
              {},
              { $set: { password: updatedPassword } },
              function (err) {
                expect(err).toBeNull();
                Test5.find({}, function (err, results) {
                  results.forEach(function (test) {
                    test.verifyPassword(updatedPassword, function (
                      err,
                      isMatch
                    ) {
                      expect(err).toBeNull();
                      expect(isMatch).toBe(true);
                      done();
                    });
                  });
                });
              }
            );
          });

          it('should encrypt password when promises not available', function (done) {
            var promise = Promise;
            Promise = null;
            var updatedPassword = 'testPwd2c';
            Test5.updateOne({}, { password: updatedPassword }, function (err) {
              expect(err).toBeNull();
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    expect(err).toBeNull();
                    expect(isMatch).toBe(true);
                    Promise = promise;
                    done();
                  });
                });
              });
            });
          });

          it('should encrypt password when updating with updateMany', function (done) {
            var updatedPassword = 'testPwd2';
            Test5.updateMany({}, { password: updatedPassword }, function (err) {
              expect(err).toBeNull();
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    expect(err).toBeNull();
                    expect(isMatch).toBe(true);
                    done();
                  });
                });
              });
            });
          });

          it('should encrypt password when updating with updateMany & $set', function (done) {
            var updatedPassword = 'testPwd2';
            Test5.updateMany(
              {},
              { $set: { password: updatedPassword } },
              function (err) {
                expect(err).toBeNull();
                Test5.find({}, function (err, results) {
                  results.forEach(function (test) {
                    test.verifyPassword(updatedPassword, function (
                      err,
                      isMatch
                    ) {
                      expect(err).toBeNull();
                      expect(isMatch).toBe(true);
                      done();
                    });
                  });
                });
              }
            );
          });
        }

        it('should encrypt password when find and updating', function (done) {
          var updatedPassword = 'testPwd2';
          Test5.findOneAndUpdate(
            { name: 'test' },
            { password: updatedPassword },
            function (err) {
              expect(err).toBeNull();
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    expect(err).toBeNull();
                    expect(isMatch).toBe(true);
                    done();
                  });
                });
              });
            }
          );
        });

        it('should clear hash when find and updating with empty password ', function (done) {
          var updatedPassword = null;
          Test5.findOneAndUpdate(
            { name: 'test' },
            { password: updatedPassword },
            function (err) {
              expect(err).toBeNull();
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  expect(test.password.length).toBe(0);
                  done();
                });
              });
            }
          );
        });

        it('should encrypt password when find and updating using $set', function (done) {
          var updatedPassword = 'testPwd2';
          Test5.findOneAndUpdate(
            { name: 'test' },
            { $set: { password: updatedPassword } },
            function (err) {
              expect(err).toBeNull();
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  test.verifyPassword(updatedPassword, function (err, isMatch) {
                    expect(err).toBeNull();
                    expect(isMatch).toBe(true);
                    done();
                  });
                });
              });
            }
          );
        });

        it('should clear hash when find and updating using $set with empty password ', function (done) {
          var updatedPassword = null;
          Test5.findOneAndUpdate(
            { name: 'test' },
            { $set: { password: updatedPassword } },
            function (err) {
              expect(err).toBeNull();
              Test5.find({}, function (err, results) {
                results.forEach(function (test) {
                  expect(test.password.length).toBe(0);
                  done();
                });
              });
            }
          );
        });

        // it('should encrypt password in subdocs when find and updating', function (done) {
        //   expect(test6.subdocs[0].verifyPasswordSync(testPwd)).toBe(true);
        //   var newPassword = 'testPwd2';
        //   var newSubdoc = new Test5({ name: 'newSubdoc', password: newPassword}, );
        //   Test6.findOneAndUpdate({_id: test6._id}, {$push: {subdocs: newSubdoc}}, {new: true}, function(err) {
        //     expect(err).toBeNull();
        //     Test6.find({}, function(err, results) {
        //       results.forEach(function (test) {
        //         expect(test.subdocs.length).toEqual(2);
        //         expect(test.subdocs[0].verifyPasswordSync(testPwd)).toBe(true);
        //         expect(test.subdocs[1].verifyPasswordSync(newPassword)).toBe(true);
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
