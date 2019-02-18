#!/usr/bin/env node

import fs = require('fs')
import jsonld = require('jsonld');
import NodeRsa = require('node-rsa');
import yargs = require('yargs');

import { sec, ob } from '../lib/props';
import { LinkedDataSignature } from '../lib/signatures';
import { RsaSignature2018 } from '../lib/suites';

const COMPACT_CONTEXT = {
  'ob': 'https://w3id.org/openbadges/v2#',
  'scd': 'https://skillcredentialspec.org/v1/',
  'sec': 'https://w3id.org/security/v1#',
  'schema': 'http://schema.org/'
}

class Signer {
    out = process.stdout;
    err = process.stderr;

    prop(obj:{[k: string]: any}, prop:string): any {
        return obj[prop];
    }

    pop(obj: {[k: string]: any}, prop: string): any {
        var value = obj[prop]
        delete obj[prop];
        return value;
    }

    utf8FileContents(filename: string): string {
        return fs.readFileSync(filename, 'utf8');
    }

    compact(document: object) {
        const docContext = this.pop(document, '@context');
        return jsonld.compact(document, COMPACT_CONTEXT, {expandContext: docContext});
    }

    pickIssuer(credential: {[k: string]: any}): {[k: string]: any} {
        return this.prop(this.prop(credential, ob.BADGE), ob.ISSUER);
    }

    setIssuerPublicKey(issuer: {[k: string]: any}, obj: object): void {
        issuer[sec.PUBLIC_KEY] = obj;
    }

    async signCredentialInFile(filename: any, options: {[k: string]: any})
    {
        var keyFile = this.prop(options, 'keyFile');
        var keyId = this.prop(options, 'keyId');

        var document  = JSON.parse(this.utf8FileContents(filename));
        var credential = await this.compact(document)

        this.setIssuerPublicKey(this.pickIssuer(credential), {
            '@id': keyId,
            '@type': ob.CRYPTOGRAPHIC_KEY,
            'sec:owner': this.pickIssuer(credential)['@id'],
            'sec:publicKeyPem': this.utf8FileContents(keyFile+'.pub')
        });

        const signature = new LinkedDataSignature(new RsaSignature2018());
        const signedCredential = await signature.sign(credential,
                                                      new NodeRsa(this.utf8FileContents(keyFile),
                                                                  'pkcs8-private-pem',
                                                                  {signingScheme: 'pkcs1-sha256'}),
                                                      keyId);

        this.out.write(JSON.stringify(signedCredential, null, 2)+"\n")
        this.err.write("Credential created.\n");
    }

    async verifyCredentialInFile(filename: any, options?: {trace?: boolean}): Promise<void> {
        options = options || {};
        var document = JSON.parse(this.utf8FileContents(filename));
        var signedCredential = await this.compact(document);

        var signature = new LinkedDataSignature(new RsaSignature2018());
        var verified = await signature.verify(signedCredential,
                                              signedCredential[ob.BADGE][ob.ISSUER][sec.PUBLIC_KEY]);
        if (!verified) {
            throw new Error("Signature verification failed.");
        } else {
            this.err.write("Signature verification succeeded!\n");
        }
    }
}

async function signCredentialInFile(filename: string, options: {[k: string]: any}) {
    var keyFile = options['keyFile'];
    var keyId = options['keyId'];

    const fileContents = fs.readFileSync(filename, 'utf8');
    var document = JSON.parse(fileContents);
    const context = document['@context'];
    delete document['@context'];
    var credential = await jsonld.compact(document, COMPACT_CONTEXT, {expandContext: context});

    const publicKeyPem = fs.readFileSync(keyFile+'.pub', 'utf8');
    var issuer = credential[ob.BADGE][ob.ISSUER]
    issuer[sec.PUBLIC_KEY] = {
        '@id': keyId,
        '@type': 'ob:CryptographicKey',
        'sec:owner': issuer['@id'],
        'sec:publicKeyPem': publicKeyPem
    };

    const privateKeyContents = fs.readFileSync(keyFile, 'utf8');
    const privateKey = new NodeRsa(privateKeyContents, 'pkcs8-private-pem', {
        signingScheme: 'pkcs1-sha256'
    });

    const signature = new LinkedDataSignature(new RsaSignature2018());
    const signedCredential = signature.sign(credential, privateKey, keyId);
    process.stdout.write(JSON.stringify(signedCredential, null, 2)+"\n")
    process.stderr.write("Credential created.\n");
}

async function main() {
    var argv = yargs
        .command({
            command: 'sign <file>',
            aliases: ['s'],
            describe: 'Sign credential in <file>',
            builder: (yargs) => yargs
                .positional('file', {
                    describe: 'The file containing the credential to sign',
                    type: 'string'
                })
                .option('k', {
                    alias: 'keyFile',
                    demandOption: true,
                    describe: 'The file containing the private key for signing',
                    type: 'string'
                })
                .option('keyId', {
                    demandOption: true,
                    describe: 'The id of the key being used for signing',
                    type: 'string'
                }),
            handler: async (argv) => {
                await new Signer().signCredentialInFile(argv.file, {keyFile: argv.keyFile, keyId: argv.keyId})
                argv._handled = true;
            }
        })
        .command({
            command: 'verify <file>',
            aliases: ['v'],
            describe: 'Verify credential signature in <file>',
            builder: (yargs) => yargs
                .positional('file', {
                    describe: 'The file containing the credential to sign',
                    type: 'string'
                }),
            handler: async (argv) => {
                await new Signer().verifyCredentialInFile(argv.file);
                argv._handled = true;
            }
        })
        .demandCommand()
        .help()
        .argv;

}


if (require.main === module) {
    main();
}
