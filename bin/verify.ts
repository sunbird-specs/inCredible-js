#!/usr/bin/env node

import fs = require('fs')
import jsonld = require('jsonld');
import yargs = require('yargs');

import { LinkedDataSignature } from '../lib/signatures';
import { RsaSignature2018 } from '../lib/suites';


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
