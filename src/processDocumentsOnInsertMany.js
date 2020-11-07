function processDocumentsOnInsertMany(documents, fields, encrypt, next) {
  documents.forEach(function (document, idx, thisArr) {
    var changed = [];
    var lastIdx = thisArr.length - 1;
    var isLastDocument = idx === lastIdx;

    // Determine list of encrypted fields that have been modified
    fields.forEach(function (field) {
      const splitField = field.split('.');
      // we are concerned only about the leftmost part
      if (document.hasOwnProperty(splitField[0])) {
        changed.push(splitField);
      }
    });

    // Create/update hash for each modified encrypted field
    var count = changed.length;
    if (count > 0) {
      changed.forEach(function (splitField) {
        var value;
        var nestedObjWithValue;
        var lastField;
        var originalField = splitField.join('.');

        splitField.forEach(function (field, idx, thisArr) {
          const lastIdx = thisArr.length - 1;
          value = value ? value[field] : document[field];
          lastField = field;
          if (idx < lastIdx) nestedObjWithValue = value;
        });

        nestedObjWithValue = nestedObjWithValue ? nestedObjWithValue : document;

        if (typeof value === 'string') {
          encrypt(originalField, value, function (err, hash) {
            if (err) return next(err);
            nestedObjWithValue[lastField] = hash;
            if (--count === 0 && isLastDocument) next();
          });
        } else {
          nestedObjWithValue[lastField] = '';
          if (--count === 0 && isLastDocument) next();
        }
      });
    } else {
      next();
    }
  });
}

module.exports = processDocumentsOnInsertMany;
