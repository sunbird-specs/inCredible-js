export class sec {
    static readonly IRI: string = 'https://w3id.org/security/v1#';
    static readonly PREFIX: string = 'sec';
    static readonly CREATED: string = sec.PREFIX+':created';
    static readonly CREATOR: string = sec.PREFIX+':creator';
    static readonly DOMAIN: string = sec.PREFIX+':domain';
    static readonly NONCE: string = sec.PREFIX+':nonce';
    static readonly PUBLIC_KEY: string = sec.PREFIX+':publicKey';
    static readonly SIGNATURE: string = sec.PREFIX+':signature';
    static readonly SIGNATURE_VALUE: string = sec.PREFIX+':signatureValue';
}


export class ob {
    static readonly IRI: string = 'https://w3id.org/openbadges/v2#';
    static readonly PREFIX: string = 'ob';

    static readonly BADGE: string = ob.PREFIX+':badge';
    static readonly ISSUER: string = ob.PREFIX+':issuer';
    static readonly CRYPTOGRAPHIC_KEY: string = ob.PREFIX+':CryptographicKey';
}


export class scd {
    static readonly IRI: string = 'https://skillcredentialsspec.org/v1#';
    static readonly PREFIX: string = 'scd';
}


export class schema {
    static readonly IRI: string = 'http://schema.org/';
    static readonly PREFIX: string = 'schema';
}
