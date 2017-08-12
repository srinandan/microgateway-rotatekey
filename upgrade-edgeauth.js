"use strict";

const util = require("util");
const debug = require("debug")("jwkrotatekey");
const commander = require('commander');
const request = require("request");
const apigeetool = require('apigeetool');
const path = require('path');

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
options.virtualhost = commander.virtualhost || 'secure';

const opts = {
    organization: options.org,
    environments: options.env,
    baseuri: options.baseuri,
    username: options.username,
    password: options.password,
    basepath: '/edgemicro-auth',
    verbose: true,
    api: 'edgemicro-auth',
    directory:  path.join(__dirname,'node_modules','microgateway-edgeauth'),
    'import-only': false,
    'resolve-modules': false,
    virtualhosts: options.virtualhost
  };

apigeetool.deployProxy(opts, function(err, res) {
    if (err) {
     	console.error(err);
     	process.exit(1);
    } else {
    	console.log("edgemicro-auth proxy upgraded");
    }
});  