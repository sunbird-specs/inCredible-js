import crypt = require('crypto');
import jsonld = require('jsonld');
import NodeRsa = require('node-rsa');


export interface SignatureSuite {

    /**
     * Returns the name of the signature suite
     */
    name(): string;

    /**
     * Given a JSON-LD document, returns the normalized representation suitable
     * for hashing etc.
     */
    normalize(document: object): Promise<string>;

    /**
     * Given a string message, returns the bytes of the hash of the message.
     */
    hash(message: string): Buffer;

    /**
     * Given a message, signs the message using the private key provided
     */
    sign(message: Buffer, privateKey: NodeRsa): Buffer;

    /**
     * Given a signature, data, and public key verifies if the signature matches
     * the data
     */
     verify(message: Buffer, signature: Buffer, publicKey: NodeRsa): boolean;
}


export class RsaSignature2018 implements SignatureSuite {
    static readonly HASH_ALG = 'sha256';

    name(): string {
        return 'RsaSignature2018';
    }

    /**
     * Normalizes the JSON-LD document according to the RDF Dataset
     * Normalization algorithm: https://json-ld.github.io/normalization/spec/
     * also known as URDNA2015
     */
    normalize(document: object): Promise<string> {
        return jsonld.canonize(document, {
            algorithm: 'URDNA2015',
            format: 'application/n-quads'
        });
    }

    hash(message: string): Buffer {
        var hasher = crypt.createHash(RsaSignature2018.HASH_ALG);
        hasher.update(new Buffer(message, 'utf8'));
        return hasher.digest();
    }

    sign(message: Buffer, privateKey: NodeRsa): Buffer {
        return privateKey.sign(message);
    }

    verify(message: Buffer, signature: Buffer, publicKey: NodeRsa): boolean {
        return publicKey.verify(message, signature);
    }
}
