"use strict";

const pem = require("pem");
const util = require("util");
const debug = require("debug")("jwkrotatekey");
const commander = require('commander');
const request = require("request");

var options = {};

commander
	.description('Rotate JWT Keys for microgateway')
    .option('-o, --org <org>', 'the organization')
    .option('-e, --env <env>', 'the environment')
    .option('-u, --username <user>', 'username of the organization admin')
    .option('-p, --password <password>', 'password of the organization admin')
    .option('-k, --kid <kid>','kid for the private/public key')
		.option('-m, --mgmtdomain <https://url:port>', 'on-premise domain and port for the management server')
		.option('-r, --runtimedomain <https://domain:port>', 'on-premise domain and port to access the proxies')
    .parse(process.argv);

if (!commander.username || !commander.password || !commander.org || !commander.env) {
	console.error("Mandatory parameters missing");
	process.exit(1);
}

if(commander.mgmtdomain && !commander.runtimedomain) {
	console.error("Apigee Edge managment server domain was provided but the runtime domain was not provided.");
	process.exit(1);
}

if(!commander.runtimedomain && commander.mgmtdomain) {
	console.error("Apigee Edge runtime domain was provided but the mangement server domain was not provided.");
	process.exit(1);
}

options.org = commander.org;
options.env = commander.env;
options.username = commander.username;
options.password = commander.password;
options.baseuri = commander.mgmtdomain || "https://api.enterprise.apigee.com";
options.kvm = "microgateway";
options.kid =  commander.kid || "2";
options.proto = "https";
options.mgmtdomain = commander.mgmtdomain;
options.runtimedomain = commander.runtimedomain;

// response: { certificate, csr, clientKey, serviceKey }
function createCert(cb) {

    const options = {
        selfSigned: true,
        days: 1
    };

    pem.createCertificate(options, cb);
}

function generateCredentialsObject(options) {
    if (options.token) {
        return {
            "bearer": options.token
        };
    } else {
        return {
            user: options.username,
            pass: options.password
        };
    }
}

function getPublicKeyURI(options) {
	if(options.runtimedomain){
		console.log("public key uri: " + util.format("%s/edgemicro-auth/publicKey",options.runtimedomain));
		return util.format("%s/edgemicro-auth/publicKey",options.runtimedomain);
	} else {
		console.log("public key uri: " + util.format("%s://%s-%s.apigee.net/edgemicro-auth/publicKey",
				options.proto, options.org, options.env));
		return util.format("%s://%s-%s.apigee.net/edgemicro-auth/publicKey",
					options.proto, options.org, options.env);
	}
}

var privateKeyURI = util.format("%s/v1/organizations/%s/environments/%s/keyvaluemaps/%s/entries/private_key",
		options.baseuri, options.org, options.env, options.kvm);
var publicKeyURI = getPublicKeyURI(options);

console.log("Checking if private key in the KVM...");
request({
    uri: privateKeyURI,
    auth: generateCredentialsObject(options),
    method: "GET"
}, function(err, res, body) {
    if (err) {
        console.error(err);
    } else {
    	console.log("Private key found");
      console.log("Checking for public key...");
      request({
            uri: publicKeyURI,
            auth: generateCredentialsObject(options),
            method: "GET"
        }, function(err, res, body) {
            if (err) {
                console.error(err);
            } else {
            	console.log("Public key found!");
            	pem.getPublicKey(body, function(err, oldPublicKey) {
            		console.log("Public Key: ");
            		console.log(oldPublicKey.publicKey);
            		console.log("Generating New key/cert pair...");
            		createCert(function(err, newkeys) {

            		    var updatekvmuri = util.format("%s/v1/organizations/%s/environments/%s/keyvaluemaps/%s",
            		        options.baseuri, options.org, options.env, options.kvm);
										console.log("update kvm uri: " + updatekvmuri);
            		    console.log("New Private Key");
            		    console.log(newkeys.serviceKey);
            		    console.log("New Public Key");
            		    console.log(newkeys.certificate);
            		    pem.getPublicKey(newkeys.certificate, function(err, newkey) {
            		        var payload = {
            		            "name": options.kvm,
            		            "encrypted": "true",
            		            "entry": [{
            		                    "name": "private_key",
            		                    "value": newkeys.serviceKey
            		                },
            		                {
            		                    "name": "private_key_kid",
            		                    "value": options.kid
            		                },
            		                {
            		                    "name": "public_key",
            		                    "value": newkeys.certificate
            		                },
            		                {
            		                    "name": "public_key1",
            		                    "value": newkey.publicKey
            		                },
            		                {
            		                    "name": "public_key1_kid",
            		                    "value": options.kid
            		                },
            		                {
            		                    "name": "public_key2",
            		                    "value": oldPublicKey.publicKey
            		                },
            		                {
            		                    "name": "public_key2_kid",
            		                    "value": "1"
            		                }
            		            ]
            		        };
            		        console.log("Upload Key cert pair to KVM");
            		        request({
            		            uri: updatekvmuri,
            		            auth: generateCredentialsObject(options),
            		            method: "POST",
            		            json: payload
            		        }, function(err, res, body) {
            		            if (err) {
            		                console.error(err);
            		            } else {
            		                console.log("Key rotation complete");
            		            }
            		        });
            		    });
            		});
            	});
            }
        });
    }
});
