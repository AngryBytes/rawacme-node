'use strict';

const crypto = require('crypto');
const pemjwk = require('pem-jwk');
const request = require('request');
const base64url = require('base64url');

// Re-export the base64 module.
exports.base64 = base64url;

// Convert DER buffer to PEM string. The header argument is one of:
//  - `RSA PUBLIC KEY`
//  - `RSA PRIVATE KEY`
//  - `CERTIFICATE`
exports.fromDer = (header, der) => {
    return (
        '-----BEGIN ' + header + '-----\n' +
        der.toString('base64').match(/.{1,64}/g).join('\n') +
        '\n-----END ' + header + '-----\n'
    );
};

// Convert PEM string to DER buffer.
exports.toDer = (pem) => {
    return new Buffer(
        pem.split(/[\r\n]+/g)
            .map((line) => line.trim())
            .filter((line) => line)
            .slice(1, -1).join(''),
        'base64'
    );
};

// Convert a PEM certificate to PEM.
exports.certFromDer = (der) => {
    return (
        '-----BEGIN CERTIFICATE-----\n' +
        der.toString('base64').match(/.{1,64}/g).join('\n') +
        '\n-----END CERTIFICATE-----\n'
    );
};

// Create a JWK object from an RSA public key.
// This method is useful during account registration.
exports.jwk = pemjwk.pem2jwk;

// Create a JWK SHA-256 thumbprint from an RSA public key.
// This method is useful during account key roll-over.
exports.jwkThumbprint = (publicKey) => {
    const jwk = exports.jwk(publicKey);
    const s = '{' +
        '"e":"' + jwk.e + '",' +
        '"kty":"' + jwk.kty + '",' +
        '"n":"' + jwk.n + '"' +
    '}';

    const hasher = crypto.createHash('sha256');
    hasher.update(s);
    return hasher.digest();
};

// Create a key authorization from a token and RSA public key.
// This method is useful for responding to challenges.
exports.keyAuthz = (token, publicKey) => {
    const thumbprint = exports.jwkThumbprint(publicKey);
    return token + '.' + base64url.encode(thumbprint);
};

// Create a base64 SHA-256 of the key authorization.
// This method is useful for responding to a dns-01 challenge.
exports.dnsKeyAuthzHash = (keyAuthz) => {
    const hasher = crypto.createHash('sha256');
    hasher.update(keyAuthz);
    const hash = hasher.digest();

    return base64url.encode(hash);
};

// Helper: Normalize JWS protected input.
const jwsInputPart = (value) => {
    if (!Buffer.isBuffer(value)) {
        if (typeof value !== 'string') {
            value = JSON.stringify(value) || '';
        }
        value = new Buffer(value);
    }
    return base64url.encode(value);
};

// Create a signed JWS object from an object using RS256.
// Input is a partial JWS object without `header` or `signature`.
// This method is useful during account key roll-over.
exports.jwsRS256 = (obj, privateKey, publicKey) => {
    const protHeader = jwsInputPart(obj.protected);
    const payload = jwsInputPart(obj.payload);

    const signer = crypto.createSign('RSA-SHA256');
    signer.update(protHeader + '.' + payload);
    const signature = signer.sign(privateKey);

    return {
        header: {
            alg: 'RS256',
            jwk: exports.jwk(publicKey)
        },
        protected: protHeader,
        payload: payload,
        signature: base64url.encode(signature)
    };
};

// Helper: Wrap a request callback to handle JSON.
// We cannot use the request `json` flag, because it annoyingly doesn't deal
// well with only one side sending JSON. Instead, rely on Content-Type.
const jsonContentTypes = [
    'application/json',
    'application/problem+json'
];
const wrapRequestCallback = (callback) => (err, res) => {
    if (res && jsonContentTypes.indexOf(res.headers['content-type']) !== -1) {
        try {
            res.body = JSON.parse(res.body.toString());
        }
        catch (e) {
            err = e;
        }
    }
    callback(err, res);
};

// Helper: Wrap a request callback to handle the nonce header.
const wrapRequestMethodCallback = (client, callback) => (err, res) => {
    if (res) {
        const nonce = res.headers['replay-nonce'];
        if (nonce) {
            client.nonce = nonce;
        }
    }
    callback(err, res);
};

// Make a GET API request. Parameters are:
//
//  - `header`: Optional extra headers.
//
// The callback signature is `(error, response)`.
exports.get = (url, params, callback) => {
    if (typeof params === 'function') {
        callback = params;
        params = null;
    }
    if (!params) {
        params = {};
    }

    return request({
        method: 'GET',
        url: url,
        encoding: null,
        headers: params.headers
    }, wrapRequestCallback(callback));
};

// Make a POST API request. Parameters are:
//
//  - `privateKey`: The account RSA private key in PEM format.
//  - `publicKey`: The account RSA public key in PEM format.
//  - `nonce`: The nonce from an earlier request.
//  - `header`: Optional extra headers.
//
// The callback signature is `(error, response)`.
exports.post = (url, body, params, callback) => {
    const signed = exports.jwsRS256({
        protected: { nonce: params.nonce },
        payload: body
    }, params.privateKey, params.publicKey);

    return request({
        method: 'POST',
        url: url,
        encoding: null,
        headers: Object.assign({
            'Content-Type': 'application/json'
        }, params.headers),
        body: new Buffer(JSON.stringify(signed))
    }, wrapRequestCallback(callback));
};

// Make GET API requests until the server no longer responsed with 202 and
// Retry-After. Parameters are:
//
//  - `header`: Optional extra headers.
//  - `onResponse`: Optional function `(res)` invoked on every response.
//
// The callback signature is `(error, response)`. Returns a handle with a
// `destroy` method which can be used to cancel polling.
exports.poll = (url, params, callback) => {
    if (typeof params === 'function') {
        callback = params;
        params = null;
    }
    if (!params) {
        params = {};
    }

    let aborted = false;

    // Make one request.
    const one = () => {
        if (aborted) {
            return;
        }

        exports.get(url, params, (err, res) => {
            if (aborted) {
                return;
            }
            if (err) {
                callback(err, null);
                return;
            }

            if (params.onResponse) {
                params.onResponse(res);
                if (aborted) {
                    return;
                }
            }

            const retryAfter = res.headers['retry-after'];
            if (res.statusCode === 202 && retryAfter) {
                schedule(retryAfter);
                return;
            }

            callback(null, res);
        });
    };

    // Schedule the next request.
    const schedule = (delay) => {
        if (/^[0-9]+$/.test(delay)) {
            delay = parseFloat(delay);
        }
        else {
            delay = Date.parse(delay) - Date.now();
        }

        delay = isFinite(delay)
            ? Math.max(1000, delay)
            : 10000;

        setTimeout(one, delay);
    };

    // Start on the next tick.
    process.nextTick(one);

    // Return the handle with destroy method.
    return {
        destroy() {
            aborted = true;
        }
    };
};

// Client class. This provides simple wrappers for the exports, merging in
// client default parameters, and rotating the nonce. In addition, directory
// resources are added as short-hand methods.
class Client {
    constructor(params) {
        this.params = params;
        this.nonce = null;
    }

    get(url, params, callback) {
        if (typeof params === 'function') {
            callback = params;
            params = null;
        }

        callback = wrapRequestMethodCallback(this, callback);
        return exports.get(url, params, callback);
    }

    post(url, body, params, callback) {
        if (typeof params === 'function') {
            callback = params;
            params = null;
        }

        const realParams = Object.create(this.params);
        realParams.nonce = this.nonce;
        Object.assign(realParams, params);

        callback = wrapRequestMethodCallback(this, callback);
        return exports.post(url, body, realParams, callback);
    }

    poll(url, params, callback) {
        if (typeof params === 'function') {
            callback = params;
            params = null;
        }

        callback = wrapRequestMethodCallback(this, callback);
        return exports.poll(url, params, callback);
    }
}

// Helper: Create a wrapped request method for the client object.
//
// Basically a version of request with the `url` argument bound, and sets
// `resource` on the body for you.
const createMethod = (resource, url) => {
    return function(body, params, callback) {
        body.resource = resource;
        return this.post(url, body, params, callback);
    };
};

// Create a client instance, returned in the callback.
//
// Only the `url` parameter is required, and should contain the URL to the ACME
// directory resource.
//
// Additional params are defaults for requests (Usually `privateKey` and
// `publicKey`.
//
// The callback signature is `(error, client)`.
exports.createClient = (params, callback) => {
    // Create the instance.
    const client = new Client(params);

    // Make the initial directory request. Also fetches the initial nonce.
    client.get(params.url, (err, res) => {
        if (!err && res.statusCode !== 200) {
            err = Error(
                'Could not fetch ACME directory, ' +
                'status code: ' + res.statusCode
            );
        }
        if (err) {
            callback(err, null);
            return;
        }

        // Iterate resources in the directory.
        const resourceMap = res.body;
        Object.keys(resourceMap).forEach((resource) => {
            const url = resourceMap[resource];

            // Build method name as camelcase resource.
            const method = resource.replace(
                /-([a-z])/g,
                (m) => m[1].toUpperCase()
            );

            // Define method on client.
            client[method] = createMethod(resource, url);
        });

        // Return.
        callback(null, client);
    });
};

// Let's Encrypt ACME URLs.
exports.LETSENCRYPT_URL =
    'https://acme-v01.api.letsencrypt.org/directory';
exports.LETSENCRYPT_STAGING_URL =
    'https://acme-staging.api.letsencrypt.org/directory';
