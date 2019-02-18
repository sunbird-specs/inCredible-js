import fs = require('fs');
import jsonld = require('jsonld');
import NodeRsa = require('node-rsa');
import { LinkedDataSignature } from './lib/signatures';
import { RsaSignature2018 } from './lib/suites';


class Resource {
    properties: {[k:string]: any}

    static wrap(properties: {[k: string]: any}): Resource {
        return new Resource(properties);
    }

    constructor(properties: {[k: string]: any}|undefined) {
        properties = properties || {}
        this.properties = properties;
    }

    public type(type: string): Resource {
        return this.put("@type", type, {checkDups: true});
    }

    public getTypes(): string[] {
        var types = this.get("@type");
        if (types.constuctor === Array) {
            return types;
        } else {
            return [types];
        }
    }

    public get(...path: string[]): any {
        var next = this.properties;
        var missing:string[] = [];

        path.forEach(function(property) {
            missing.push(property);
            next = next[property];
            if (next == null) {
                throw new Error("Resource is missing property "+ missing.join("."));
            }
        });

        return next;
    }

    public getR(...path: string[]): Resource {
        return Resource.wrap(this.get(...path));
    }

    public has(...path: string[]): boolean {
        var container = this.get(...path.slice(0, -1))
        return container.hasOwnProperty(path.slice(-1)[0]);
    }

    public put(property: string, value: any, options?: {checkDups: boolean}): Resource {
        if (this.properties.hasOwnProperty(property)) {
            this.mergePropertyValue(property, value);
        } else {
            this.properties[property] = value;
        }
        return this;
    }

    public obj(): object {
        return this.properties;
    }

    private mergePropertyValue(property: string, value: any, options?: {checkDups: boolean}): void {
        options = options || { checkDups: false };
        var present = this.properties[property];

        if (present != null && present.constructor === Array) { // presently a list
            if (value.constructor === Array) {
                present.concat(present, value);
            } else {
                if (!options.checkDups || !present.includes(value)) {
                    present.push(value);
                }
            }
        } else if (present != null) {                           // presently a scalar
            var valueList = [];
            valueList.push(present);
            valueList.push(value);
            this.properties[present] = valueList;
        } else {                                                // presently absent
            this.properties[present] = value;
        }
    }
}


export class Credential {
    r: Resource;

    constructor(compactCredential: {[k: string]: any}) {
        this.r = Resource.wrap(compactCredential);
    }

    static async fromFile(filePath: string): Promise<Credential> {
        const fileContents = fs.readFileSync(filePath, 'utf8');
        var document = JSON.parse(fileContents);
        const context = document['@context'];
        delete document['@context'];
        var credential = await jsonld.compact(document, context);
        return new Credential(credential);
    }

    async sign(keyId: string, privateKeyData: Buffer, makeSignatory?: boolean): Promise<SignedCredential> {
        makeSignatory = (makeSignatory != null) ? makeSignatory : false;
        var privateKey = new NodeRsa(privateKeyData, 'pkcs8-private-pem');

        const signature = new LinkedDataSignature(new RsaSignature2018());
        var awardingBody = new AwardingBody(this.r.getR('ob:badge', 'ocd:awardingBody'));

        if (makeSignatory) {
            if (!awardingBody.isSignatory() || awardingBody.findKeyWithId(keyId) == null) {
                awardingBody.makeSignatory({
                    "@id": keyId,
                    "@type": "ob:CryptographicKey",
                    "sec:owner": awardingBody.r.get("@id"),
                    "sec:publicKeyPem": privateKey.exportKey("pkcs8-public-pem")
                });
            }
        }

        return new SignedCredential(signature.sign(this.r.obj(), privateKey, keyId))
    }
}


export class SignedCredential extends Credential {
    async verify(): Promise<boolean> {
        const ldSignature = this.r.getR("ocd:signature");

        var awardingBody = new AwardingBody(this.r.get("ob:badge", "ocd:awardingBody"));
        var publicKey = awardingBody.findKeyWithId(ldSignature.get("sec:creator"));
        assert(publicKey != null, "Could not find public key for signature creator");

        const signature = new LinkedDataSignature(new RsaSignature2018());
        return signature.verify(this.r.obj(), publicKey!["sec:publicKeyPem"]);
    }
}


export class AwardingBody {
    r: Resource;

    constructor(properties: Resource) {
        this.r = properties;
    }

    public isSignatory(): boolean {
        var types = this.r.getTypes();
        return types.includes("ob:Extension") &&
                types.includes("ocd:SignatoryExtension") &&
                this.r.has("ocd:publicKey");
    }

    public makeSignatory(publicKey: object) {
        this.r
            .type('ob:Extension')
            .type('ocd:SignatoryExtension')
            .put('ocd:publicKey', publicKey);
    }

    public findKeyWithId(keyId: string): {[k: string]: any}|null {
        var keys = this.r.get("ocd:publicKey");
        if (keys.constructor !== Array) {
            keys = [keys];
        }

        var matched = keys.filter(function(key: {[k: string]: any}, index: number, array: any[]) {
            return key.hasOwnProperty("@id") && key["@id"] == keyId;
        });

        if (matched.length == 0) {
            return null;
        } else if (matched.length == 1) {
            return matched[0];
        } else {
            throw Error("Found multiple keys with @id: "+keyId);
        }
    }
}


function assert(condition: boolean, message?: string) {
    if (!condition) {
        message = message || "Assertion failure!";
        throw new Error(message);
    }
}
