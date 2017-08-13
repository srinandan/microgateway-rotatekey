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
    .option('-v, --virtualhost <virtualhost>', 'virtual host of the proxy')
    .option('-b, --baseuri <baseuri>', 'baseuri for management apis')
    .parse(process.argv);

if (!commander.username || !commander.password || !commander.org || !commander.env) {
	console.error("Mandatory parameters missing");
	process.exit(1);
}

options.org = commander.org;
options.env = commander.env;
options.username = commander.username;
options.password = commander.password;
options.baseuri = commander.baseuri || "https://api.enterprise.apigee.com";
options.proto = "https";
options.kvm = 'microgateway';
options.kid = '1';
options.virtualhost = commander.virtualhost || 'secure';

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

var publicKeyURI = util.format('https://%s-%s.apigee.net/edgemicro-auth/publicKey', options.org, options.env);

console.log("Checking for certificate...");
request({
    uri: publicKeyURI,
    auth: generateCredentialsObject(options),
    method: "GET"
}, function(err, res, body) {
    if (err) {
        console.error(err);
    } else {
    	console.log("Certificate found!");
    	pem.getPublicKey(body, function(err, publicKey) {
    		console.log(publicKey.publicKey);
    		var updatekvmuri = util.format("%s/v1/organizations/%s/environments/%s/keyvaluemaps/%s",
    		    options.baseuri, options.org, options.env, options.kvm);
    		var payload = {
    		    "name": options.kvm,
    		    "encrypted": "true",
    		    "entry": [
    		        {
    		            "name": "private_key_kid",
    		            "value": options.kid
    		        },
    		        {
    		            "name": "public_key1",
    		            "value": publicKey.publicKey
    		        },
    		        {
    		            "name": "public_key1_kid",
    		            "value": options.kid
    		        }
    		    ]
    		};    		
    		request({
    		    uri: updatekvmuri,
    		    auth: generateCredentialsObject(options),
    		    method: "PUT",
    		    json: payload
    		}, function(err, res, body) {
    		    if (err) {
    		        console.error(err);
    		    } else {
    		        console.log("KVM update complete");
    		    }
    		});
    	});
    }
   }
);