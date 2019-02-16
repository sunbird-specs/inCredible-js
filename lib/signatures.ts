import { SignatureSuite } from './suites';
import NodeRsa = require('node-rsa');


export interface SignatureProtocol {
    /**
     * Given a document and a set of verification options, creates a
     * hash of the document and the verification options
     *
     * @param canonicalDoc the JSON-LD document in canonical string form
     * @param [options] options to use:
     *            [creator]: the IRI of the creator of the signature
     *            [created]: the time at which the signature is being created,
     *                 may be null|undefined
     *            [nonce]: a nonce value to include in the signature to prevent
     *                 replay attacks
     *            [domain]: a domain for which this signature is valid
     * @return Buffer containing bytes of the hash
     */
    createVerifyHash(canonicalDoc: string, options: {[k: string]: string}): Promise<Buffer>;

    /**
     * Given a JSON-LD document, a private key and an id for the key returns
     * the signed document according to the signature protocol
     */
    sign(document: object, privateKey: NodeRsa, keyId: string): Promise<object>;

    /**
     * Given a signed JSON-LD document, verifies the signature according to the
     * signature protocol
     */
    verify(signedDocument: {[k: string]: any}): Promise<boolean>;
}


export class LinkedDataSignature implements SignatureProtocol {

    suite: SignatureSuite;
    trace: boolean;

    constructor(suite: SignatureSuite) {
        this.suite = suite;
        this.trace = true;
    }

    async createVerifyHash(canonicalDoc: string, options: {[k: string]: string}): Promise<Buffer> {
        if (!options.hasOwnProperty('creator')) {
            throw ReferenceError("Must provide 'creator' option");
        }

        var cleanOpts: {[k: string]: string} = {
            'sec:creator': options['creator'],
            'sec:created': options.hasOwnProperty('created') ? options['created']:new Date().toUTCString()
        }
        if (options.hasOwnProperty('nonce')) {
            cleanOpts['sec:nonce'] = options['nonce'];
        }
        if (options.hasOwnProperty('domain')) {
            cleanOpts['sec:domain'] = options['domain'];
        }

        // Step 4.1: Canonicalise the options
        const canonicalOpts = await this.suite.normalize(cleanOpts);
        if (this.trace) {
            process.stderr.write("Norm opts:\n"+canonicalOpts+"\n");
        }
        // Step 4.2: compute hash of the options
        const optsHash = this.suite.hash(canonicalOpts);
        // Step 4.3: compute hash of the document
        const docHash = this.suite.hash(canonicalDoc);
        return Buffer.concat([optsHash, docHash])
    }

    /**
     * Given a JSON-LD document and a NodeRSA PrivateKey, will return the
     * signed document according to the LinkedDataSignature 1.0
     * specification. This implementation uses the RsaSignature2018
     * signature suite.
     *
     * @param document JSON-LD document in compact representation
     * @param privateKey NodeRsa privateKey object
     * @param keyId: The JSON-LD @id (identifier) of the private/public keypair
     *     used
     *
     * @return signed document
     */
    async sign(document: {[k: string]: any}, privateKey: NodeRsa, keyId: string): Promise<object> {
        // Following the algorithm at:
        // https://w3c-dvcg.github.io/ld-signatures/#signature-algorithm
        // 16 Feb 2019
        // Step 1: copy the credential
        // TODO: create a proper copy
        var output = document;
        // Step 2: Canonicalise
        const canonicalDoc = await this.suite.normalize(document);
        if (this.trace) {
            process.stderr.write("Normalized:\n"+canonicalDoc);
        }
        // Step 3: Create verify hash, setting creator and created options
        const created = new Date().toUTCString();
        const tbs = await this.createVerifyHash(canonicalDoc, {
            creator: keyId,
            created: created
        });
        if (this.trace) {
            process.stderr.write("TBS:\n"+tbs.toString('base64'));
        }
        const signatureValue = this.suite.sign(tbs, privateKey);
        output['ocd:signature'] = this.createSignature(keyId, created, signatureValue);
        return output;
    }

    async verify(signedDocument: {[k: string]: any}): Promise<boolean> {
        // Following the algorithm at:
        // https://w3c-dvcg.github.io/ld-signatures/#signature-verification-algorithm
        // 16 Feb 2019
        // Step 1: Get the cryptographic key and rsa object
        // Step 1b: verifying owner from sec_key is left as an exercise
        const issuerKey = signedDocument['ob:badge']['ocd:awardedBy']['ocd:publicKey']
        const publicKey = new NodeRsa(issuerKey['sec:publicKeyPem'], 'pkcs8-public-pem', {
            signingScheme: 'pkcs1-sha256'
        });
        // Step 2: copy signed document into document
        // TODO: make a deep copy
        var document = signedDocument;
        // Step 3: removing the signature node from the document for comparison
        const signature = document['ocd:signature']
        delete document['ocd:signature'];
        // Step 4: canonicalise the document
        const canonicalDoc = await this.suite.normalize(document);
        if (this.trace) {
            process.stderr.write("Normalized:\n"+canonicalDoc+"\n");
        }
        // Step 5: Create the verify hash using the signature options
        const tbv = await this.createVerifyHash(canonicalDoc, {
            creator: signature['sec:creator'],
            created: signature['sec:created']
        });
        if (this.trace) {
            process.stderr.write("TBV:\n"+tbv.toString('base64')+"\n");
        }
        // Step 6: verify
        const signatureValue = new Buffer(signature['sec:signatureValue'], 'base64');
        return this.suite.verify(tbv, signatureValue, publicKey);
    }

    /**
     * Creates a LinkedDataSignature object given a signatureValue
     */
    createSignature(creator: string, created: string, signatureValue: Buffer): object {
        return {
            "@type": this.suite.name(),
            "sec:creator": creator,
            "sec:created": created,
            "sec:signatureValue": signatureValue.toString('base64')
        };
    }
}
