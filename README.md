# mongoose-bcrypt #

Mongoose plugin adding an encrypted password field using bcrypt-nodejs by default but with options to add multiple fields with configurable encryption per field.

## Installation ##

```
$ npm install mongoose-bcrypt
```

## Default usage ##
Adds encrypted `password` field with instance methods `verifyPassword(password,callback)` and `verifyPasswordSync(password)`

```javascript
var demoSchema = new mongoose.Schema({
    demoField: String
});
demoSchema.plugin(require('mongoose-bcrypt'));	// Adds { password: String } to schema

var Demo = mongoose.model('Demo', demoSchema);

var newDemo = new Demo({
  demoField: 'someValue',
  password: 'mySecretPassword'
}).save(function(err, demo) {					// Stores newDemo with encrypted password
	if (!err) {
		demo.verifyPassword('mySecretPassword', function(err, isMatch) {
			if (!err) {
				console.log(isMatch ? "Valid" : "Invalid");		// Logs 'Valid'
			}
		});
		var syncMatch = demo.verifyPasswordSync('bogusPassword');
		console.log(syncMatch ? "Valid" : "Invalid");			// Logs 'Invalid'
	};
});
```
## Add schema options ##
To set additional schema options, define the password field with desired options **before** loading the plugin. The module will simply attach to the existing field.
```javascript
var demoSchema = new mongoose.Schema({
    demoField: String,
	password: { type: String, required: true }
});
demoSchema.plugin(require('mongoose-bcrypt'));	// Will attach to predefined password field
```
## Use custom field name##
To use a field other than password, specify the field name when loading the plugin. This will also rename the corresponding verify methods using CamelCasing. The following example adds encrypted field `secret` and adds instance methods `verifySecret` and `verifySecretSync`. 
```javascript
demoSchema.plugin(require('mongoose-bcrypt'), { field: 'secret' });	// Add 'secret' field
```
## Add multiple fields ##
Specify an array of field names to add multiple encrypted fields to a schema. Verification methods will be added for each field as described above.
```javascript
demoSchema.plugin(require('mongoose-bcrypt'), { fields: ['password', 'secret'] });	// Add 'password' and 'secret' fields
```
## Set bcrypt rounds ##
Rounds determine the complexity used for encryption with bcrypt-nodejs (see [bcrypt-nodejs](https://www.npmjs.org/package/bcrypt-nodejs "bcrypt-nodejs") docs). To override the default, specificy the desired number of rounds when plugin is loaded.
```javascript
demoSchema.plugin(require('mongoose-bcrypt'), { rounds: 8 });	// Will use bcrypt with 8 rounds
```
## Set bcrypt rounds per field ##
The default number of rounds is used for all encrypted fields unless a field specifies otherwise. The following example will encrypt password with 9 rounds but secretA and secretB with 5 rounds.
```javascript
var demoSchema = new mongoose.Schema({
    demoField: String,
	password: { type: String, required: true, rounds: 9 }
});
demoSchema.plugin(require('mongoose-bcrypt'), { 
	fields: ['password', 'secretA', 'secretB'], 
	rounds: 5 
});
```
