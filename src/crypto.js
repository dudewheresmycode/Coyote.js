'use strict';

var forge = require('node-forge');


function generateCSR(domain, callback){

  // generate a key pair
  var keys = forge.pki.rsa.generateKeyPair({bits: 2048, e: 0x10001, workers: -1});

  // create a certification request (CSR)
  var csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: 'commonName', value: domain }]);

  // sign certification request
  csr.sign(keys.privateKey);

  // verify certification request
  var verified = csr.verify();

  // convert certification request to PEM-format
  var pem = forge.pki.certificationRequestToPem(csr);

  var derBuffer = forge.pki.pemToDer(pem).getBytes();
  var keyPem = forge.pki.privateKeyToPem(keys.privateKey);

  return callback(null, {csr:derBuffer, csr_pem:pem, key:keyPem});
}



function generateKeyPair(opts, callback){
  var bits = opts.bits || 2048;
  var rsa = forge.pki.rsa;
  rsa.generateKeyPair({bits: bits, e: 0x10001, workers: -1}, function(err, keypair){
    var pem = forge.pki.privateKeyToPem(keypair.privateKey);
    var n = keypair.privateKey.n.toByteArray();
    callback(err, {key:pem, modulus:trimleft(n)});
  });
}

function signData(data, pem, callback){
  var privateKey = forge.pki.privateKeyFromPem(pem);
  var md = forge.md.sha256.create();
  md.update(data, 'utf8');
  var signature = privateKey.sign(md);
  return forge.util.encode64(signature);
}

function genereateHash(data){
  var md = forge.md.sha256.create();
  md.update(data);
  var out = md.digest();
  return forge.util.encode64(out.data);
}
function certificateFromDer(input){
  var asn1 = forge.asn1.fromDer(input);
  var crt = forge.pki.certificateFromAsn1(asn1);
  return forge.pki.certificateToPem(crt);
}

function trimleft(arr){
  var idx = arr.findIndex(function(n){ return Math.abs(n) > 0; });
  if(idx > 0){ return arr.slice(idx); }
  return arr;
}

module.exports = {
  signData: signData,
  certificateFromDer: certificateFromDer,
  generateCSR: generateCSR,
  genereateHash: genereateHash,
  generateKeyPair: generateKeyPair
};
