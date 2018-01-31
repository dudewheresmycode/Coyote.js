var options = {prod:false}; //use staging
var client = new Acme(options);
var logEle = document.getElementById('log');
var emailEle = document.getElementById('email');
var domainEle = document.getElementById('domain');

function handleError(err){
  console.error(err);
  logEle.innerHTML += "Error: "+err+"\n\n";
  return;
}
function log(str){
  logEle.innerHTML += str+"\n";
  logEle.scrollTop = 9999999;
}

log("Ready!");

function start(e){
  e.preventDefault();
  log("Generating account key...");
  var bits = 2048; //or 4096
  client.generateAccountKey({bits:bits}, function(err,key){
    if(err){ return handleError(err); }
    console.log(err,key);
    log("Generated a "+bits+" bit key!");

    log("Registering user: "+emailEle.value+" (email optional)");
    client.registerUser({email:emailEle.value}, function(err, result){
      if(err){ return handleError(err); }
      log("User registration success!");


      log("Registering domain: "+domainEle.value);
      client.registerDomain({domain:domainEle.value}, function(err, result){
        if(err){ return handleError(err); }
        log("Domain registration success!");
        console.log(err, result);


      });

    });

  });
  return false;

}
