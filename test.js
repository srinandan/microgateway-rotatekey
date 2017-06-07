'use strict';

const pem = require('pem');
const util = require('util');
const debug = require('debug')('jwkrotatekey');
const request = require('request');

var options = {
	org: 'demo',
	env: 'test',
	baseuri: 'https://api.enterprise.apigee.com',
	username: '',
	password: '',
	kvm: 'microgateway',
	kid: '1'
}

// response: { certificate, csr, clientKey, serviceKey }
function createCert(cb) {

  const options = {
    selfSigned: true,
    days: 1
  };

  pem.createCertificate(options, cb);
}

function generateCredentialsObject(options) {
  if(options.token) {
    return {
      'bearer': options.token
    };
  } else {
    return {
      user: options.username,
      pass: options.password
    };
  }
}


var uri = util.format('%s/v1/organizations/%s/environments/%s/keyvaluemaps/%s/entries/private_key',
    options.baseuri, options.org, options.env, options.kvm);

request({
  uri: uri,
  auth: generateCredentialsObject(options),
  method: 'GET'
}, function(err, res, body) {
  if (err) {
    console.error(err);
  } else {
  	createCert(function(err, keys) {
  		var updatekvmuri = util.format('%s/v1/organizations/%s/environments/%s/keyvaluemaps/%s',
    		options.baseuri, options.org, options.env, options.kvm);
  		
  		pem.getPublicKey (keys.certificate, function(err, key) {
	  		var payload = {
					  "name" : options.kvm,
					  "encrypted": 'true',
					  "entry" : [ 
					  {
					    "name" : "private_key",
					    "value" : keys.serviceKey
					  }, 
					  {
					    "name" : "private_key_kid",
					    "value" : options.kid
					  }, 
					  {
					    "name" : "public_key1",
					    "value" : key.publicKey
					  },
					  {
					    "name" : "public_key1_kid",
					    "value" : "1"
					  },
					  {
					  	"name": "public_key",
					  	"value": keys.certificate
					  }				  
					 ]
			};
	  		request({
	  		  uri: updatekvmuri,
	  		  auth: generateCredentialsObject(options),
	  		  method: 'POST',
	  		  json: payload
	  		}, function(err, res, body) {
				if (err) {
					console.error(err);
				} else {
					console.log('all good!');
				}
			});
  		});
  	});
  }
});

