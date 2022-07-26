[![huntr](https://cdn.huntr.dev/huntr_security_badge_mono.svg)](https://huntr.dev)
[![Known Vulnerabilities](https://snyk.io/test/github/knokbak/cf-jwt/badge.svg)](https://snyk.io/test/github/knokbak/cf-jwt)

[![CF-JWT](https://nodei.co/npm/cf-jwt.png)](https://npmjs.com/package/cf-jwt)

# CF-JWT
### A JWT library for Cloudflare Workers. Compliant with [RFC 7519](https://tools.ietf.org/html/rfc7519).

## What are JWTs?
JWTs (or "JSON Web Tokens") are an easy way to issue and verify information tokens on-the-fly. JWTs can be signed by one party (an "issuer"), then verified by another (the "audience").

## What are JWTs good for?
- Most short-lived one-use authentication tokens.
- Long-lives tokens that can be revoked or blacklisted.
- General data storage where data should not be editable by the user.

## What should JWTs NOT be used for?
- Long-lived authentication tokens, or authentication tokens that can be reused.
- Any type of authentication token that cannot be revoked or blacklisted.
- To store any sensitive data - unless you are encrypting the JWT. If you are, you *should* be OK.

## How do I use this library?

### Importing the library
```ts
import JWT from 'cf-jwt';
// or, if you're still old-school:
const JWT = require('cf-jwt');
```

### Creating a JWT
```ts
const jwt = await JWT.sign({
    hello: 'world!',
    some: 'lovely data',
    that: 'i can sign!',
}, 'what-a-lovely-secret', {
    algorithm: 'HS256',
    expiresAt: new Date(Date.now() + 60000), // 60 seconds
});
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkISIsInNvbWUiOiJsb3ZlbHkgZGF0YSIsInRoYXQiOiJpIGNhbiBzaWduISIsImlhdCI6MTY1ODQzMzEyNywiZXhwIjoxNjU4NDMzMTg4fQ.u5ejuvjb_t0F2uQUcOGfwtcxUpgIdpQEBQEdwDF7gQE
```

### Verifying a JWT
```ts
const jwt = await JWT.verify(jwtString, 'what-a-lovely-secret', {
    algorithms: ['HS256'],
});
/**
 * {
 *     hello: 'world!',
 *     some: 'lovely data',
 *     that: 'i can sign!',
 *     iat: 2022-07-21T19:54:55.000Z,
 *     exp: 2022-07-21T19:55:56.000Z
 * }
 */
```

## API Reference

### JWT.sign(payload: any, secret: string, options: JWTSignOptions): Promise\<string\>
### JWT.signSync(payload: any, secret: string, options: JWTSignOptions): string
Signs an object and returns a JWT string.

```ts
const uuid = crypto.randomUUID();
const signedJWT = await JWT.sign({
    grant: 'access to my cookie jar',
}, 'chocolate chip cookies!!!!!', {
    algorithm: 'HS256', // in most cases, this should be sufficient
    expiresAt: new Date(Date.now() + (60000 * 60)), // expires in 60 minutes
    notBefore: new Date(Date.now() + 30000), // becomes valid in 30 seconds
    audience: 'the entire world of course!',
    issuer: 'me :D',
    jwtid: uuid, // make sure this is random!
    subject: 'my best friend',
});
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJncmFudCI6ImFjY2VzcyB0byBteSBjb29raWUgamFyIiwiaWF0IjoxNjU4NDM0MDk1LCJleHAiOjE2NTg0Mzc2OTYsIm5iZiI6MTY1ODQzNDEyNSwiYXVkIjoidGhlIGVudGlyZSB3b3JsZCBvZiBjb3Vyc2UhIiwiaXNzIjoibWUgOkQiLCJqdGkiOiI0OGY3ODg4Yy1mMmVkLTRhODAtOWNjMS1hZmQzYzI0ZGY0ZTMiLCJzdWIiOiJteSBiZXN0IGZyaWVuZCJ9.-IaNMkkf2lYyMGQC737Ig1yxr0K6bh3POraBAToDSAc
```

#### Parameters
- `payload` (`Object`): The object to sign.
- `secret` (`string`): The secret to use to sign the object.
- `options` (`Object`): An object containing options for the JWT.
- `options.algorithm` (`string`): The algorithm to use to sign the object. Available options are `HS256` (SHA-256), `HS384` (SHA-384) and `HS512` (SHA-512).
- `options.expiresAt`? (`Date`): The time at which the JWT should expire. Compliant libraries and clients should reject the JWT if it is used AFTER this date. Defaults to `null`.
- `options.notBefore`? (`Date`): The time before which the JWT should not be accepted. Compliant libraries and clients should reject the JWT if it is used BEFORE this date. Defaults to `null`.
- `options.audience`? (`string`): The audience of the JWT. This is used to tell compliant libraries and clients who the JWT is meant to be accepted by. Defaults to `null`.
- `options.issuer`? (`string`): The issuer of the JWT. This is used to tell compliant libraries and clients who created the JWT. Defaults to `null`.
- `options.jwtid`? (`string`): The JWT's unique identifier. If set, you should ensure this value is unique. Defaults to `null`.
- `options.subject`? (`string`): The subject of the JWT. Defaults to `null`.

**Returns:** The new JWT string.
**Throws:** An error if one or more incorrect parameters are provided.

### JWT.verify(jwt: string, secret: string, options: JWTSignOptions): Promise\<any\>
### JWT.verifySync(jwt: string, secret: string, options: JWTSignOptions): any
Verifies a JWT string and returns the payload as an object.

```ts
const jwt = await JWT.verify(signedJWT, 'chocolate chip cookies!!!!!', {
    algorithms: ['HS256'], // list all the algorithms you want to allow
    audience: ['the entire world of course!'], // list all the audiences you want to allow
    issuer: ['me :D'], // list all the issuers you want to allow
    jwtid: [uuid], // list all the jwtids you want to allow
    subject: ['my best friend'], // list all the subjects you want to allow
});
```

#### Parameters
- `jwt` (`string`): The JWT to verify.
- `secret` (`string`): The secret to use to verify the JWT.
- `options` (`Object`): An object containing options for the verification process.
- `options.algorithms` (`string[]`): A list of all algorithms to allow. Available options are `HS256` (SHA-256), `HS384` (SHA-384) and `HS512` (SHA-512).
- `options.audience`? (`string` | `string[]`): The audiences to allow for this JWT.
- `options.issuer`? (`string` | `string[]`): The issuers to allow for this JWT.
- `options.jwtid`? (`string` | `string[]`): The allowed set of JWT IDs.
- `options.subject`? (`string` | `string[]`): The subjects allowed for this JWT.

**Returns:** The payload of the JWT.
**Throws:** An error if one or more issues are found with the JWT.

## BSD-3 License
Copyright (c) 2022, knokbak    
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

1. **Redistributions of source code must retain the above copyright notice**, this 
   list of conditions and the following disclaimer. 

2. **Redistributions in binary form must reproduce the above copyright notice**, 
   this list of conditions and the following disclaimer in the documentation 
   and/or other materials provided with the distribution. 

3. **Neither the name of the copyright holder nor the names of its 
   contributors may be used to endorse or promote products** derived from 
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE 
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
