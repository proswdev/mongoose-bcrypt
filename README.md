# mongoose-bcrypt #

Mongoose plugin encrypting field(s) with bcrypt and providing methods to encrypt and verify.

## Installation ##

```
$ npm install mongoose-bcrypt
```

## Default usage ##
Adds encrypted `password` field with instance methods `verifyPassword(password,callback)` and `verifyPasswordSync(password)` and static method `encryptPassword(password,callback)`. Asynchronous methods support both callbacks and promises.

```javascript
var demoSchema = new mongoose.Schema({
  demoField: String
});

// Add { password: String } to schema
demoSchema.plugin(require('mongoose-bcrypt'));

var Demo = mongoose.model('Demo', demoSchema);

// Create demo instance with encrypted password
Demo.create({
  demoField: 'someValue',
  password: 'mySecretPassword'
}, function(err, demo) {
  if (!err) {
    // Verify password with callback => Valid (callback)
    demo.verifyPassword('mySecretPassword', function(err, valid) {
      if (err) {
        console.log(err)
      } else if (valid) {
        console.log('Valid (callback)');
      } else {
        console.log('Invalid (callback)');
      }
    });
    // Verify password using promise => Valid (promise)
    demo.verifyPassword('mySecretPassword')
      .then(function(valid) {
        if (valid) {
          console.log('Valid (promise)');
        } else {
          console.log('Invalid (promise)');
        }
      })
      .catch(function(err) {
        console.log(err);
      });
    // Verify password synchronously => Invalid (sync)
    var valid = demo.verifyPasswordSync('bogusPassword');
    if (valid) {
      console.log('Valid (sync)');
    } else {
      console.log('Invalid (sync)');
    }
  }
});
// The password field is automatically encrypted when an instance is saved
// Use the static encryption method to return encrypted password values for
// other use. The values will be encrypted using the actual bcrypt settings
// assigned to the password field (see bcrypt rounds below)  
Demo.encryptPassword('anotherSecret', function(err, encryptedValue) {
  if (err) {
    console.log(err);
  } else {
    // Do something with encrypted data
    console.log('Encrypted password is ' + encryptedValue);
  }
});
// Using promises
Demo.encryptPassword('anotherSecret')
  .then(function(encryptedValue) {
    // Do something with encrypted data
    console.log('Encrypted password is ' + encryptedValue);
  })
  .catch(function(err) {
    console.log(err);
  });
});
```
## Encrypting existing fields ##
To encrypt one or more existings fields or set additional schema options, add the bcrypt option to
each schema type **before** loading the plugin. The module will simply attach to the existing fields
and create encrypt and verify methods for each field using camelCasing. The following example
encrypts fields `password`, `secret` and `foo.bar.baz` and creates instance methods
`encryptPassword`, `verifyPassword`, `verifyPasswordSync`, `verifySecret`,`verifySecretSync`,
`verifyFooBarBaz` and `verifyFooBarBazSync`, in addition to static methods `encryptPassword`,
`encryptSecret` and `encryptFooBarBaz`.

```javascript
var demoSchema = new mongoose.Schema({
  demoField: String,
  password: { type: String, required: true, bcrypt: true },
  secret: { type: String, bcrypt: true },
  foo: {
    bar: {
      baz: { type: String, bcrypt: true }
    }
  }
});
// Attach to predefined password and secret field
demoSchema.plugin(require('mongoose-bcrypt'));
```
## Adding encrypted fields ##
Specify an array of field names when loading the plugin to add new encrypted fields to a schema. The module will attach to existing fields if already defined but create new encrypted fields otherwise. Encryption and verification methods will be added for each field as described above.

```javascript
// Add 'secretA', 'secretB' and 'baz.bar.foo' fields
demoSchema.plugin(require('mongoose-bcrypt'), { 
  fields: ['secretA', 'secretB', 'baz.bar.foo'] 
});
```
## Set bcrypt rounds ##
Rounds determine the complexity used for encryption with bcrypt-nodejs (see [bcrypt-nodejs](https://www.npmjs.org/package/bcrypt-nodejs "bcrypt-nodejs") docs). To override the default, specificy the desired number of rounds when plugin is loaded.
```javascript
// Use bcrypt with 8 rounds
demoSchema.plugin(require('mongoose-bcrypt'), { rounds: 8 });
```
## Set bcrypt rounds per field ##
The default number of rounds is used for all encrypted fields unless a field specifies otherwise. The following example will encrypt `secretA` with 9 rounds, `secretB` with 6 rounds and both `secretC` and `secretD` with the default 5 rounds.
```javascript
var demoSchema = new mongoose.Schema({
  demoField: String,
  secretA: { type: String, required: true, rounds: 9 },
  secretB: { type: String, bcrypt: true, rounds: 6 },
  secretC: { type: String, bcrypt: true },
  bested: {
    secret: { type: String, bcrypt: true, rounds: 6 },
  }
});
demoSchema.plugin(require('mongoose-bcrypt'), {
  fields: ['secretA', 'secretD'],
  rounds: 5
});
```
## Update Queries ##
Mongoose-bcrypt will automatically encrypt the appropriate fields when a document is created or saved using the regular static and instance methods. With mongoose versions >= 4.1.3, the plugin also provides automatic encryption when updates are performed using update queries.  
```javascript
var newPwd = 'updatedPassword';
Demo.update({}, { password: newPwd }, 
  function(err) { 
    ... 
  });

Demo.update({}, { $set: { password: newPwd }}, 
  function(err) { 
    ... 
  });

Demo.findOneAndUpdate({ demoField: 'someValue' }, { password: newPwd }, 
  function(err) { 
    ... 
  });

Demo.findOneAndUpdate({ demoField: 'someValue' }, ( $set: { password: newPwd }},  
  function(err) { 
    ... 
  });
```