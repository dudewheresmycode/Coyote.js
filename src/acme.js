'use strict';

var assert = require('assert'),
    fs = require('fs'),
    path = require('path'),
    util = require('util'),

    // parseLinks = require('parse-links'),
    async = require('async'),
    superagent = require('superagent'),
    _ = require('underscore');

var crypto = require('./crypto.js');

var CONFIG = {
  "CA_PROD": "https://acme-v01.api.letsencrypt.org",
  "CA_STAGING": "https://acme-staging.api.letsencrypt.org",
  "LE_AGREEMENT": "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf",
  "CHALLENGE_DIR": ".well-known/acme-challenge"
};

function AcmeError(reason, errorOrMessage) {
  assert.strictEqual(typeof reason, 'string');
  assert(errorOrMessage instanceof Error || typeof errorOrMessage === 'string' || typeof errorOrMessage === 'undefined');

  Error.call(this);
  Error.captureStackTrace(this, this.constructor);

  this.name = this.constructor.name;
  this.reason = reason;
  if (typeof errorOrMessage === 'undefined') {
      this.message = reason;
  } else if (typeof errorOrMessage === 'string') {
      this.message = errorOrMessage;
  } else {
      this.message = 'Internal error';
      this.nestedError = errorOrMessage;
  }
}

util.inherits(AcmeError, Error);
AcmeError.INTERNAL_ERROR = 'Internal Error';
AcmeError.EXTERNAL_ERROR = 'External Error';
AcmeError.ALREADY_EXISTS = 'Already Exists';
AcmeError.NOT_COMPLETED = 'Not Completed';
AcmeError.FORBIDDEN = 'Forbidden';

// http://jose.readthedocs.org/en/latest/
// https://www.ietf.org/proceedings/92/slides/slides-92-acme-1.pdf
// https://community.letsencrypt.org/t/list-of-client-implementations/2103

function Acme(options) {
    assert.strictEqual(typeof options, 'object');

    this.caOrigin = options.prod ? CONFIG.CA_PROD : CONFIG.CA_STAGING;
    this.accountKeyPem = null; // Buffer
    this.email = options.email;
}

Acme.prototype.getNonce = function (callback) {
    superagent.get(this.caOrigin + '/directory').timeout(30 * 1000).end(function (error, response) {
        if (error && !error.response) return callback(error);
        if (response.statusCode !== 200) return callback(new Error('Invalid response code when fetching nonce : ' + response.statusCode));

        return callback(null, response.headers['Replay-Nonce'.toLowerCase()]);
    });
};

// urlsafe base64 encoding (jose)
function urlBase64Encode(string) {
    return string.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64(str) {
    var buf = util.isBuffer(str) ? str : new Buffer(str);
   return urlBase64Encode(buf.toString('base64'));
}

var debug = console.log;

Acme.prototype.sendSignedRequest = function (url, payload, callback, buffer) {
    assert.strictEqual(typeof url, 'string');
    assert.strictEqual(typeof payload, 'string');
    assert.strictEqual(typeof callback, 'function');

    assert(util.isBuffer(this.accountKeyPem));

    var that = this;
    var header = {
        alg: 'RS256',
        jwk: {
            e: b64(Buffer.from([0x01, 0x00, 0x01])), // exponent - 65537
            kty: 'RSA',
            n: b64(that.accountKeyModulus)
        }
    };

    var payload64 = b64(payload);

    this.getNonce(function (error, nonce) {
        if (error) return callback(error);

        debug('sendSignedRequest: using nonce %s for url %s', nonce, url);

        var protected64 = b64(JSON.stringify(_.extend({ }, header, { nonce: nonce })));

        var signature64 = urlBase64Encode(crypto.signData(protected64 + '.' + payload64, that.accountKeyPem));

        var data = {
            header: header,
            protected: protected64,
            payload: payload64,
            signature: signature64
        };

        var req = superagent.post(url);
        if(buffer){
          req = req.on('request', function () { this.xhr.responseType = 'blob'; });
        }

        req.set('Content-Type', 'application/x-www-form-urlencoded').send(JSON.stringify(data)).timeout(30 * 1000).end(function (error, res) {
            if (error && !error.response) return callback(error); // network errors
            callback(null, res);
        });

    });
};

Acme.prototype.updateContact = function (registrationUri, callback) {
    assert.strictEqual(typeof registrationUri, 'string');
    assert.strictEqual(typeof callback, 'function');

    debug('updateContact: %s %s', registrationUri, this.email);

    // https://github.com/ietf-wg-acme/acme/issues/30
    var payload = {
        resource: 'reg',
        contact: [ ],
        agreement: CONFIG.LE_AGREEMENT
    };
    if(this.email){
      payload.contact.push('mailto:' + that.email);
    }


    var that = this;
    this.sendSignedRequest(registrationUri, JSON.stringify(payload), function (error, result) {
        if (error) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, 'Network error when registering user: ' + error.message));
        if (result.statusCode !== 202) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, util.format('Failed to update contact. Expecting 202, got %s %s', result.statusCode, result.text)));

        debug('updateContact: contact of user updated to %s', that.email);

        callback();
    });
};

Acme.prototype.setAccountKey = function(opts, callback){
  this.accountKeyPem = Buffer.from(opts.key);
  this.accountKeyModulus = Buffer.from(opts.modulus, 'hex');
  callback(null);
}

Acme.prototype.generateAccountKey = function(opts, callback){
  var that = this;
  var bits = opts.bits || 2048;

  crypto.generateKeyPair({bits:bits}, function(err,result){
    that.accountKeyPem = Buffer.from(result.key);
    that.accountKeyModulus = Buffer.from(result.modulus, 'hex');
    callback(err, result);
  });

}


Acme.prototype.registerUser = function (opts, callback) {

    // assert.strictEqual(typeof email, 'string');
    assert.strictEqual(typeof callback, 'function');

    var that = this;
    if(opts.email){
      that.email = opts.email;
    }

    var payload = {
        resource: 'new-reg',
        contact: [ ],
        agreement: CONFIG.LE_AGREEMENT
    };

    if(this.email){
      payload.contact.push('mailto:' + that.email);
    }

    debug('registerUser: %s', that.email);

    that.sendSignedRequest(that.caOrigin + '/acme/new-reg', JSON.stringify(payload), function (error, result) {
      if (error) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, 'Network error when registering user: ' + error.message));
      console.log(error, result);
      if (result.statusCode === 409) return that.updateContact(result.headers.location, callback); // already exists
      if (result.statusCode !== 201) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, util.format('Failed to register user. Expecting 201, got %s %s', result.statusCode, result.text)));
      debug('registerUser: registered user %s', that.email);
      callback();
    });

};

Acme.prototype.registerDomain = function (opts, callback) {

  assert.strictEqual(typeof opts.domain, 'string');
  assert.strictEqual(typeof callback, 'function');

  var payload = {
      resource: 'new-authz',
      identifier: {
          type: 'dns',
          value: opts.domain
      }
  };

  debug('registerDomain: %s', opts.domain);

  this.sendSignedRequest(this.caOrigin + '/acme/new-authz', JSON.stringify(payload), function (error, result) {
      if (error) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, 'Network error when registering domain: ' + error.message));
      if (result.statusCode === 403) return callback(new AcmeError(AcmeError.FORBIDDEN, result.body.detail));
      if (result.statusCode !== 201) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, util.format('Failed to register user. Expecting 201, got %s %s', result.statusCode, result.text)));

      debug('registerDomain: registered %s', opts.domain);

      callback(null, result.body);
  });
};

Acme.prototype.prepareChallenge = function (opts, callback) {

  var challenge = opts.challenge;
  var domain = opts.domain;

  debug('prepareChallenge: preparing for challenge', challenge);
  var token = challenge.token;
  var that = this;
  assert(util.isBuffer(that.accountKeyPem));

  var jwk = {
      e: b64(Buffer.from([0x01, 0x00, 0x01])), // Exponent - 65537
      kty: 'RSA',
      n: b64(that.accountKeyModulus)
  };

  var thumbprint = urlBase64Encode(crypto.genereateHash(JSON.stringify(jwk)));
  var keyAuthorization = token + '.' + thumbprint;

  if(opts.type=='dns'){
    var txt_record = urlBase64Encode(crypto.genereateHash(keyAuthorization));
    callback(null, {keyauth:keyAuthorization, txt:txt_record, domain:util.format('_acme-challenge.%s',domain)});
  }else if(opts.type=='http'){
    callback(null, {keyauth:keyAuthorization, file:path.join(CONFIG.CHALLENGE_DIR,token)});
  }else{
    callback(new AcmeError(AcmeError.INTERNAL_ERROR, "Unkown type"));
  }


}



Acme.prototype.notifyChallengeReady = function (opts, callback) {
  var challenge = opts.challenge;
  var type = opts.type || 'dns';
  // var keyAuthorization = opts.keyauth;

  // assert.strictEqual(typeof keyAuthorization, 'string');
  assert.strictEqual(typeof challenge, 'object');
  assert.strictEqual(typeof callback, 'function');

  debug('keyAuthorization: %s', keyAuthorization);
  debug('Notify Challenge Uri: %s', challenge.uri);

  var that = this;
  var jwk = {
      e: b64(Buffer.from([0x01, 0x00, 0x01])), // Exponent - 65537
      kty: 'RSA',
      n: b64(that.accountKeyModulus)
  };
  var thumbprint = urlBase64Encode(crypto.genereateHash(JSON.stringify(jwk)));
  var keyAuthorization = challenge.token + '.' + thumbprint;

  var payload = {
      resource: 'challenge',
      keyAuthorization: keyAuthorization
  };
  console.log('challenge payload', payload);

  this.sendSignedRequest(challenge.uri, JSON.stringify(payload), function (error, result) {
    if (error) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, 'Network error when notifying challenge: ' + error.message));
    console.log("result", error, result);
    // if (result.statusCode !== 202) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, util.format('Failed to notify challenge. Expecting 202, got %s %s', result.statusCode, result.text)));
    callback();
  });
};

Acme.prototype.waitForChallenge = function (opts, callback) {
  var challenge = opts.challenge;

  assert.strictEqual(typeof challenge, 'object');
  assert.strictEqual(typeof callback, 'function');

  debug('waitingForChallenge: %j', challenge);

  async.retry({ times: 10, interval: 5000 }, function (retryCallback) {
    debug('waitingForChallenge: getting status');

    superagent.get(challenge.uri).timeout(30 * 1000).end(function (error, result) {
      if (error && !error.response) {
          debug('waitForChallenge: network error getting uri %s', challenge.uri);
          return retryCallback(new AcmeError(AcmeError.EXTERNAL_ERROR, error.message)); // network error
      }
      if (result.statusCode !== 202) {
          debug('waitForChallenge: invalid response code getting uri %s', result.statusCode);
          return retryCallback(new AcmeError(AcmeError.EXTERNAL_ERROR, 'Bad response code:' + result.statusCode));
      }

      debug('waitForChallenge: status is "%s %j', result.body.status, result.body);

      if (result.body.status === 'pending') return retryCallback(new AcmeError(AcmeError.NOT_COMPLETED));
      else if (result.body.status === 'valid') return retryCallback();
      else return retryCallback(new AcmeError(AcmeError.EXTERNAL_ERROR, 'Unexpected status: ' + result.body.status));
    });
  }, function retryFinished(error) {
      // async.retry will pass 'undefined' as second arg making it unusable with async.waterfall()
      callback(error);
  });
};

Acme.prototype.createKeyAndCsr = function (opts, callback) {
  var domain = opts.domain;
  assert.strictEqual(typeof domain, 'string');
  assert.strictEqual(typeof callback, 'function');
  var that = this;
  crypto.generateCSR(domain, function(err,resp){
    console.log(resp);
    that.csrData = Buffer.from(resp.csr, 'binary');
    that.csrKey = Buffer.from(resp.key);
    callback(null, resp);
  });
};

// https://community.letsencrypt.org/t/public-beta-rate-limits/4772 for rate limits
Acme.prototype.signCertificate = function (opts, callback) {
  var domain = opts.domain;
  var csrDer = opts.csr;
  var that = this;
  debug('signCertificate: sending new-cert request: %s', domain);

  assert.strictEqual(typeof domain, 'string');
  assert(util.isBuffer(that.csrData));
  assert.strictEqual(typeof callback, 'function');



  var payload = {
    resource: 'new-cert',
    csr: b64(that.csrData)
  };

  debug('signCertificate: sending new-cert request');

  this.sendSignedRequest(this.caOrigin + '/acme/new-cert', JSON.stringify(payload), function (error, result) {
      if (error) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, 'Network error when signing certificate: ' + error.message));
      // 429 means we reached the cert limit for this domain
      if (result.statusCode !== 201) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, util.format('Failed to sign certificate. Expecting 201, got %s %s', result.statusCode, result.text)));

      var certUrl = result.headers.location;
      if(certUrl){
        return callback(null, {result:result, type:"url", cert:null, url:certUrl});
      }

      var fileReader = new FileReader();
      fileReader.onload = function() {
        callback(null, {result:result, type:"cert", url:null, cert:crypto.certificateFromDer(this.result)});
      };
      fileReader.readAsBinaryString(result.xhr.response);

  }, true); //enable buffer
};

// TODO: download the chain in a loop following 'up' header
// Acme.prototype.downloadChain = function (linkHeader, callback) {
//     if (!linkHeader) return new AcmeError(AcmeError.EXTERNAL_ERROR, 'Empty link header when downloading certificate chain');
//
//     debug('downloadChain: linkHeader %s', linkHeader);
//
//     var linkInfo = parseLinks(linkHeader);
//     if (!linkInfo || !linkInfo.up) return new AcmeError(AcmeError.EXTERNAL_ERROR, 'Failed to parse link header when downloading certificate chain');
//
//     var intermediateCertUrl = linkInfo.up.startsWith('https://') ? linkInfo.up : (this.caOrigin + linkInfo.up);
//
//     debug('downloadChain: downloading from %s', intermediateCertUrl);
//
//     superagent.get(intermediateCertUrl).buffer().parse(function (res, done) {
//         var data = [ ];
//         res.on('data', function(chunk) { data.push(chunk); });
//         res.on('end', function () { res.text = Buffer.concat(data); done(); });
//     }).timeout(30 * 1000).end(function (error, result) {
//         if (error && !error.response) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, 'Network error when downloading certificate'));
//         if (result.statusCode !== 200) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, util.format('Failed to get cert. Expecting 200, got %s %s', result.statusCode, result.text)));
//
//         var chainDer = result.text;
//         var chainPem = execSync('openssl x509 -inform DER -outform PEM', { input: chainDer }); // this is really just base64 encoding with header
//         if (!chainPem) return callback(new AcmeError(AcmeError.INTERNAL_ERROR, safe.error));
//
//         callback(null, chainPem);
//     });
// };

Acme.prototype.downloadCertificate = function (domain, certUrl, callback) {
    assert.strictEqual(typeof domain, 'string');
    assert.strictEqual(typeof certUrl, 'string');
    assert.strictEqual(typeof callback, 'function');


    var that = this;

    superagent.get(certUrl).buffer().parse(function (res, done) {
        var data = [ ];
        res.on('data', function(chunk) { data.push(chunk); });
        res.on('end', function () { res.text = Buffer.concat(data); done(); });
    }).timeout(30 * 1000).end(function (error, result) {
        if (error && !error.response) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, 'Network error when downloading certificate'));
        if (result.statusCode === 202) return callback(new AcmeError(AcmeError.INTERNAL_ERROR, 'Retry not implemented yet'));
        if (result.statusCode !== 200) return callback(new AcmeError(AcmeError.EXTERNAL_ERROR, util.format('Failed to get cert. Expecting 200, got %s %s', result.statusCode, result.text)));

        var certificateDer = result.text;

        safe.fs.writeFileSync(path.join(outdir, domain + '.der'), certificateDer);
        debug('downloadCertificate: cert der file for %s saved', domain);

        var certificatePem = execSync('openssl x509 -inform DER -outform PEM', { input: certificateDer }); // this is really just base64 encoding with header
        if (!certificatePem) return callback(new AcmeError(AcmeError.INTERNAL_ERROR, safe.error));

        that.downloadChain(result.header['link'], function (error, chainPem) {
            if (error) return callback(error);

            var certificateFile = path.join(outdir, domain + '.cert');
            var fullChainPem = Buffer.concat([certificatePem, chainPem]);
            if (!safe.fs.writeFileSync(certificateFile, fullChainPem)) return callback(new AcmeError(AcmeError.INTERNAL_ERROR, safe.error));

            debug('downloadCertificate: cert file for %s saved at %s', domain, certificateFile);

            callback();
        });
    });
};

// Acme.prototype.setAccountKeyPem = function(key){
//   this.accountKeyPem = key;
// }


exports = module.exports = Acme;
