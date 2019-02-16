#!/usr/bin/env node

import fs = require('fs')
import jsonld = require('jsonld');
import NodeRsa = require('node-rsa');
import yargs = require('yargs');

import { LinkedDataSignature } from '../lib/signatures';
import { RsaSignature2018 } from '../lib/suites';


async function signCredentialInFile(filename: string, outFile: string, options: object) {
    var keyFile = options.keyFile;
    var keyId = options.keyId;

    const fileContents = fs.readFileSync(filename, 'utf8');
    var document = JSON.parse(fileContents);
    const context = document['@context'];
    delete document['@context'];
    var credential = await jsonld.compact(document, context);

    const publicKeyPem = fs.readFileSync(keyFile+'.pub', 'utf8');
    credential['ob:badge']['ocd:awardedBy']['ocd:publicKey'] = {
        '@id': keyId,
        '@type': 'ob:CryptographicKey',
        'sec:owner': credential['ob:badge']['ocd:awardedBy']['@id'],
        'publicKeyPem': publicKeyPem
    };

    const privateKeyContents = fs.readFileSync(keyFile, 'utf8');
    const privateKey = new NodeRsa(privateKeyContents, 'pkcs8-private-pem', {
        signingScheme: 'pkcs1-sha256'
    });

    const signature = new LinkedDataSignature(new RsaSignature2018());
    const signedCredential = signature.sign(credential, privateKey, keyId);
    process.stdout.write(JSON.stringify(signedCredential, 2)+"\n")
    process.stderr.write("Credential created.\n");
}

async function verifyCredentialInFile (filename: string, trace?: boolean): Promise<void> {
    const fileContents = fs.readFileSync(filename, 'utf8');
    var document = JSON.parse(fileContents);
    const context = document['@context'];
    delete document['@context'];
    var signedCredential = await jsonld.compact(document, context);
    var signature = new LinkedDataSignature(new RsaSignature2018());
    var verified = await signature.verify(signedCredential);
    if (!verified) {
        throw new Error("Signature verification failed");
    } else {
        process.stdout.write("Signature verification succeeded!\n");
    }
}

async function main() {
    var argv = yargs.argv;
    try {
        await verifyCredentialInFile(argv._[0]);
    } catch(e) {
        console.log(e);
    }
}


if (require.main === module) {
    main();
}
