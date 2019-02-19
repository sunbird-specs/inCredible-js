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

    async signCredentialInFile(filename: any, options: {[k: string]: any}) {
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

    async normalizeCredentialInFile(filename: any, algorithm: string): Promise<void> {
        var document = JSON.parse(this.utf8FileContents(filename));
        var credential = await this.compact(document);

        var normalized = await jsonld.normalize(credential, {
            algorithm: algorithm,
            format: 'application/n-quads'
        });
        this.out.write(normalized+"\n");
        this.err.write('Credential normalized using '+algorithm+"\n");
    }
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
                await new Signer().signCredentialInFile(argv.file,
                                                        {keyFile: argv.keyFile, keyId: argv.keyId});
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
        .command({
            command: 'normalize <file>',
            aliases: ['n'],
            describe: 'Normalize credential in <file>',
            builder: (yargs) => yargs
                .positional('file', {
                    describe: 'The file containing the credential to normalize',
                    type: 'string'
                })
                .option('urdna2015', {
                    alias: 'd15',
                    describe: 'Use URDNA2015 RDF Dataset Normalization algorithm',
                    type: 'boolean',
                    default: undefined,
                })
                .option('urgna2012', {
                    alias: 'g12',
                    describe: 'Use older URGNA2012 RDF Dataset Normalization algorithm',
                    type: 'boolean',
                    default: undefined
                })
                .conflicts('urdna2012', 'urdna2015'),
            handler: async (argv) => {
                var algorithm = argv.urgna2012 ? 'URGNA2012' : 'URDNA2015';
                await new Signer().normalizeCredentialInFile(argv.file, algorithm);
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
