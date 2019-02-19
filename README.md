# skillcredjs
Skill credential library in JS

## To install after checking out source code

```shell
$ npm install .
$ npm link
```

## To sign a credential

```shell
credential sign -k {keyFile} --keyId {keyId} {credentialFile} > {signedCredentialFile}.json
```

## To verify a credential

```shell
credential verify {signedCredentialFile}
```

# To normalize a credential

```shell
credential normalize {credentialFile}
```

