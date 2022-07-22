/*
 * Copyright (c) 2022 https://github.com/knokbak
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import { Algorithm } from './types';
import { algo as CryptoJS, enc as CryptoJSEncoders } from 'crypto-js';
import Base64URL from 'base64url';

export default class JWT {
    public static signSync(
        payload: any,
        secret: string,
        options: {
            algorithm: Algorithm;
            expiresAt?: Date;
            notBefore?: Date;
            audience?: string;
            issuer?: string;
            jwtid?: string;
            subject?: string;
        }
    ): string {
        if (!payload) {
            throw new Error('payload is required');
        }
        if (typeof payload !== 'object') {
            throw new Error('payload must be an object');
        }
        if (!secret) {
            throw new Error('secret is required');
        }
        if (typeof secret !== 'string') {
            throw new Error('secret must be a string');
        }
        if (!options) {
            throw new Error('options is required');
        }
        if (typeof options !== 'object') {
            throw new Error('options must be an object');
        }
        if (!options.algorithm) {
            throw new Error('options.algorithm is required');
        }

        const header = {
            alg: options.algorithm,
            typ: 'JWT',
        };
        payload = JWT.buildPayload(payload, options);

        const encodedHeader = JWT.encodeSegment(header);
        const encodedPayload = JWT.encodeSegment(payload);
        const segments: string[] = [encodedHeader, encodedPayload];
        const signed = JWT.signData(
            segments.join('.'),
            secret,
            options.algorithm
        );
        segments.push(signed);

        return segments.join('.');
    }

    public static sign(
        payload: any,
        secret: string,
        options: {
            algorithm: Algorithm;
            expiresAt?: Date;
            notBefore?: Date;
            audience?: string;
            issuer?: string;
            jwtid?: string;
            subject?: string;
        }
    ): Promise<string> {
        return new Promise((resolve, reject) => {
            try {
                const token = JWT.signSync(payload, secret, options);
                resolve(token);
            } catch (err) {
                reject(err);
            }
        });
    }

    public static verifySync(
        token: string,
        secret: string,
        options?: {
            algorithms?: Algorithm[];
            audience?: string | string[];
            issuer?: string | string[];
            jwtid?: string | string[];
            subject?: string | string[];
            clockTolerance?: number;
        }
    ): any {
        options = options || {};
        if (!options.clockTolerance) {
            options.clockTolerance = 0;
        }

        if (!token) {
            throw new Error('token is required');
        }
        if (typeof token !== 'string') {
            throw new Error('token must be a string');
        }
        if (!secret) {
            throw new Error('secret is required');
        }
        if (typeof secret !== 'string') {
            throw new Error('secret must be a string');
        }

        const segments = token.split('.');
        if (segments.length !== 3) {
            throw new Error(
                'Tokens must have 3 segments separated by a dot (header.payload.signature). See https://tools.ietf.org/html/rfc7519#section-4.1.'
            );
        }
        const header = JWT.decodeSegment(segments[0]);
        const payload = JWT.decodeSegment(segments[1]);
        const signature = segments[2];
        const issues = [];

        if (
            options.algorithms &&
            options.algorithms.indexOf(header.alg) === -1
        ) {
            issues.push(
                `The token\'s algorithm is not explicitly allowed in the list of allowed algorithms. Used: ${
                    header.alg
                }. Allowed: [${options.algorithms.join(', ')}].`
            );
        }
        if (options.audience) {
            if (Array.isArray(options.audience)) {
                if (options.audience.indexOf(payload.aud) === -1) {
                    issues.push(
                        `The token\'s audience is not allowed. Used: ${
                            payload.aud
                        }. Allowed: [${options.audience.join(', ')}].`
                    );
                }
            } else {
                if (payload.aud !== options.audience) {
                    issues.push(
                        `The token\'s audience is not allowed. Used: ${payload.aud}. Allowed: ${options.audience}.`
                    );
                }
            }
        }
        if (options.issuer) {
            if (Array.isArray(options.issuer)) {
                if (options.issuer.indexOf(payload.iss) === -1) {
                    issues.push(
                        `The token\'s issuer is not explicitly allowed in the list of allowed issuers. Used: ${
                            payload.iss
                        }. Allowed: [${options.issuer.join(', ')}].`
                    );
                }
            } else {
                if (payload.iss !== options.issuer) {
                    issues.push(
                        `The token\'s issuer does not match the expected issuer. Used: ${payload.iss}. Expected: ${options.issuer}.`
                    );
                }
            }
        }
        if (options.jwtid) {
            if (Array.isArray(options.jwtid)) {
                if (options.jwtid.indexOf(payload.jti) === -1) {
                    issues.push(
                        `The token\'s jwtid is not explicitly allowed in the list of allowed jwtids. Used: ${
                            payload.jti
                        }. Allowed: [${options.jwtid.join(', ')}].`
                    );
                }
            } else {
                if (payload.jti !== options.jwtid) {
                    issues.push(
                        `The token\'s jwtid does not match the expected jwtid. Used: ${payload.jti}. Expected: ${options.jwtid}.`
                    );
                }
            }
        }
        if (options.subject) {
            if (Array.isArray(options.subject)) {
                if (options.subject.indexOf(payload.sub) === -1) {
                    issues.push(
                        `The token\'s subject is not explicitly allowed in the list of allowed subjects. Used: ${
                            payload.sub
                        }. Allowed: [${options.subject.join(', ')}].`
                    );
                }
            } else if (payload.sub !== options.subject) {
                issues.push(
                    `The token\'s subject does not match the expected subject. Used: ${payload.sub}. Expected: ${options.subject}.`
                );
            }
        }
        if (!isNaN(payload.exp)) {
            if (
                payload.exp + options.clockTolerance <
                Math.floor(Date.now() / 1000)
            ) {
                issues.push(
                    `The token has expired. It was valid until ${new Date(
                        payload.exp * 1000
                    ).toString()}.`
                );
            }
            payload.exp = new Date(payload.exp * 1000);
        }
        if (!isNaN(payload.nbf)) {
            if (payload.nbf > Math.floor(Date.now() / 1000)) {
                issues.push(
                    `The token is not yet valid. It is not valid until ${new Date(
                        payload.nbf * 1000
                    ).toString()}.`
                );
            }
            payload.nbf = new Date(payload.nbf * 1000);
        }
        if (!isNaN(payload.iat)) {
            payload.iat = new Date(payload.iat * 1000);
        }
        if (!JWT.verifySignature(signature, secret, segments, header)) {
            issues.push(
                "The token's signature is invalid. It's likely been modified or manipulated and should not be trusted."
            );
        }

        if (issues.length > 0) {
            throw new Error(
                `One or more issues were found whilst verifying the JWT:\n${issues.join(
                    '\n'
                )}\n`
            );
        } else {
            return payload;
        }
    }

    public static verify(
        token: string,
        secret: string,
        options?: {
            algorithms?: Algorithm[];
            audience?: string | string[];
            issuer?: string | string[];
            jwtid?: string | string[];
            subject?: string | string[];
            clockTolerance?: number;
        }
    ): Promise<any> {
        return new Promise((resolve, reject) => {
            try {
                const payload = JWT.verifySync(token, secret, options);
                resolve(payload);
            } catch (err) {
                reject(err);
            }
        });
    }

    private static verifySignature(
        signature: string,
        secret: string,
        segments: string[],
        header: any
    ): boolean {
        const algo = JWT.determineAlgorithm(header.alg);
        const signingInput = segments.slice(0, 2).join('.');
        const hmac = CryptoJS.HMAC.create(algo, secret);
        hmac.update(signingInput);
        const computedSignature = hmac
            .finalize()
            .toString(CryptoJSEncoders.Base64);
        /*const str = Buffer.from(computedSignature, 'base64').toString(
            'base64url'
        );*/
        const str = Base64URL.fromBase64(computedSignature);
        return signature === str;
    }

    private static decodeSegment(segment: string): any {
        //const str = Buffer.from(segment, 'base64url').toString('utf8');
        const str = Base64URL.decode(segment);
        return JSON.parse(str);
    }

    private static signData(
        data: any,
        secret: string,
        algorithm: Algorithm
    ): string {
        const algo = JWT.determineAlgorithm(algorithm);
        const hmac = CryptoJS.HMAC.create(algo, secret);
        hmac.update(data);
        const finalized = hmac.finalize();
        /*const out = Buffer.from(
            finalized.toString(CryptoJSEncoders.Base64),
            'base64'
        ).toString('base64url');*/
        const out = Base64URL.fromBase64(
            finalized.toString(CryptoJSEncoders.Base64)
        );
        return out;
    }

    private static determineAlgorithm(algorithm: Algorithm): any {
        switch (algorithm) {
            case 'HS256':
                return CryptoJS.SHA256;
            case 'HS384':
                return CryptoJS.SHA384;
            case 'HS512':
                return CryptoJS.SHA512;
            default:
                throw new Error('Unknown algorithm provided!');
        }
    }

    private static encodeSegment(segment: any): string {
        const str = JSON.stringify(segment);
        //const out = Buffer.from(str, 'utf8').toString('base64url');
        const out = Base64URL.encode(str);
        return out;
    }

    private static buildPayload(data: any, options: any): any {
        let payload = data;
        payload.iat = JWT.getNow();
        if (options.expiresAt) {
            if (!(options.expiresAt instanceof Date)) {
                throw new Error('expiresAt must be a Date');
            }
            payload.exp = Math.ceil(options.expiresAt.getTime() / 1000);
        }
        if (options.notBefore) {
            if (!(options.notBefore instanceof Date)) {
                throw new Error('notBefore must be a Date');
            }
            payload.nbf = Math.floor(options.notBefore.getTime() / 1000);
        }
        if (options.audience) {
            if (typeof options.audience !== 'string') {
                throw new Error('audience must be a string');
            }
            payload.aud = options.audience;
        }
        if (options.issuer) {
            if (typeof options.issuer !== 'string') {
                throw new Error('issuer must be a string');
            }
            payload.iss = options.issuer;
        }
        if (options.jwtid) {
            if (typeof options.jwtid !== 'string') {
                throw new Error('jwtid must be a string');
            }
            payload.jti = options.jwtid;
        }
        if (options.subject) {
            if (typeof options.subject !== 'string') {
                throw new Error('subject must be a string');
            }
            payload.sub = options.subject;
        }
        return payload;
    }

    private static getNow(): number {
        return Math.floor(Date.now() / 1000);
    }
}
