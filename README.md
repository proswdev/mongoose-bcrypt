# mongoose-bcrypt #

Mongoose plugin encrypting field(s) with bcrypt and providing methods to encrypt and verify.

## Installation ##

```
$ npm install mongoose-bcrypt
```

## Default usage ##
Adds encrypted `password` field with instance methods `verifyPassword(password,callback)` and `verifyPasswordSync(password)` and static method `encryptPassword(password,callback)`

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
    // Verify password with callback
    demo.verifyPassword('mySecretPassword', function(err, valid) {
      if (!err)
        console.log(valid ? "ValidAsync" : "InvalidAsync"); //=>'ValidAsync'
    });
    // Verify password synchronously
    var valid = demo.verifyPasswordSync('bogusPassword');
    console.log(valid ? "ValidSync" : "InvalidSync"); //=>'InvalidSync'
  }
});

// The password field is automatically encrypted when an instance is saved
// Use the static encryption method to return encrypted password values for
// other use. The values will be encrypted using the actual bcrypt settings
// assigned to the password field (see bcrypt rounds below)  
Demo.encryptPassword('anotherSecret', function(err, encryptedValue) {
	if (!err) {
		// Do something with encrypted data
		console.log('Encrypted password is ' + encryptedValue);
	}
}); 
```
## Encrypting existing fields ##
To encrypt one or more existings fields or set additional schema options, add the bcrypt option to each schema type **before** loading the plugin. The module will simply attach to the existing fields and create encrypt and verify methods for each field using camelCasing. The following example encrypts fields `password` and `secret` and creates instance methods `verifyPassword`, `verifyPasswordSync`, `verifySecret` and `verifySecretSync`, in addition to static methods `encryptPassword` and `encryptSecret`. 
```javascript
var demoSchema = new mongoose.Schema({
  demoField: String,
  password: { type: String, required: true, bcrypt: true },
  secret: { type: String, bcrypt: true }
});
// Attach to predefined password and secret field
demoSchema.plugin(require('mongoose-bcrypt'));
```
## Adding encrypted fields ##
Specify an array of field names when loading the plugin to add new encrypted fields to a schema. The module will attach to existing fields if already defined but create new encrypted fields otherwise. Encryption and verification methods will be added for each field as described above. 
```javascript
// Add 'secretA' and 'secretB' fields
demoSchema.plugin(require('mongoose-bcrypt'), { fields: ['secretA', 'secretB'] });
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
	secretC: { type: String, bcrypt: true }
});
demoSchema.plugin(require('mongoose-bcrypt'), { 
	fields: ['secretA', 'secretD'], 
	rounds: 5 
});
```
