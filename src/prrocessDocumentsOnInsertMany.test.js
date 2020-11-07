var processDocumentsOnInsertMany = require('./processDocumentsOnInsertMany');

describe('Process Documents on Model.insertMany', function () {
  var documents, fields, encrypt, next, testDocument1, testDocument2, err, hash;

  beforeEach(function () {
    var testPwd = '123';
    fields = ['password'];

    testDocument1 = {
      name: 'test1',
      password: testPwd,
      index: 0,
    };

    testDocument2 = {
      name: 'test2',
      password: testPwd,
      index: 0,
    };
    documents = [testDocument1, testDocument2];

    hash = testPwd + 'hashed';

    next = jest.fn();

    err = null;

    encrypt = jest.fn(function (original, value, cb) {
      cb(err, hash);
    });
  });

  it('should call next when no fileds were changed', function () {
    fields = [];
    processDocumentsOnInsertMany(documents, fields, encrypt, next);

    expect(next).toHaveBeenCalled();
  });

  it('should call next if field is not present in any document', function () {
    fields = ['abc'];
    processDocumentsOnInsertMany(documents, fields, encrypt, next);

    expect(next).toHaveBeenCalled();
  });

  describe('if field(s) is/are present in the documents', function () {
    describe('if a value is not a string', function () {
      beforeEach(function () {
        testDocument1.password = 123;
      });
      it('it should make the value a "" in the document', function () {
        processDocumentsOnInsertMany(documents, fields, encrypt, next);

        expect(testDocument1.password).toEqual('');
      });

      it('should call next if last document reached', function () {
        processDocumentsOnInsertMany(documents, fields, encrypt, next);

        expect(next).toHaveBeenCalled();
      });
    });

    describe('if value is a string', function () {
      it('should pass en error if encrypting failed', function () {
        err = 'error';

        processDocumentsOnInsertMany(documents, fields, encrypt, next);

        expect(next).toHaveBeenCalledWith(err);
      });

      it('should encrypt fields successfully', function () {
        processDocumentsOnInsertMany(documents, fields, encrypt, next);

        expect(testDocument1.password).toEqual(hash);
        expect(testDocument2.password).toEqual(hash);
      });

      it('should call next if last document reached', function () {
        processDocumentsOnInsertMany(documents, fields, encrypt, next);

        expect(next).toHaveBeenCalled();
      });
    });
  });
});
