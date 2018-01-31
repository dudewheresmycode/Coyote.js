var Acme = require('../');
var options = {prod:false}; //use staging
var client = new Acme(options);
client.generateAccountKey({bits:2048}, function(err,key){
  console.log(err, key);
});
