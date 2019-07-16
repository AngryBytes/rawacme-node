import crypto from "crypto";
import pemjwk, { RSA_JWK } from "pem-jwk";
import request, { Request, Response } from "request";
import base64url from "base64url";

/// Re-export of the `base64url` module.
export const base64 = base64url;

/// JWS algorithms we support.
export type JwsAlg = "RS256";

/// The types of PEM headers we support.
export type PemHeader = "RSA PUBLIC KEY" | "RSA PRIVATE KEY" | "CERTIFICATE";

/// Callback signature for returning a response.
export type ResponseCallback = (error: any, response: Response) => void;

/// Convert DER buffer to PEM string.
export const fromDer = (header: PemHeader, der: Buffer): string => {
  return (
    "-----BEGIN " +
    header +
    "-----\n" +
    der
      .toString("base64")
      .match(/.{1,64}/g)!
      .join("\n") +
    "\n-----END " +
    header +
    "-----\n"
  );
};

/// Convert PEM string to DER buffer.
export const toDer = (pem: string): Buffer => {
  const base64 = pem
    .split(/[\r\n]+/g)
    .map(line => line.trim())
    .filter(line => line)
    .slice(1, -1)
    .join("");
  return new Buffer(base64, "base64");
};

/// Create a JWK object from an RSA public key.
/// This function is useful during account registration.
export const jwk = pemjwk.pem2jwk;

/// Create a JWK SHA-256 thumbprint from an RSA public key.
/// This function is useful during account key roll-over.
export const jwkThumbprint = (publicKey: string): Buffer => {
  // We must guarantee order of properties when hashing here.
  const { e, kty, n } = jwk(publicKey);
  const json = `{"e":"${e}","kty":"${kty}","n":"${n}"}`;

  const hasher = crypto.createHash("sha256");
  hasher.update(json);
  return hasher.digest();
};

/// Create a key authorization from a token and RSA public key.
/// This function is useful for responding to challenges.
export const keyAuthz = (token: string, publicKey: string): string => {
  const thumbprint = jwkThumbprint(publicKey);
  return token + "." + base64url.encode(thumbprint);
};

/// Create a base64 SHA-256 of the key authorization.
/// This function is useful for responding to a dns-01 challenge.
export const dnsKeyAuthzHash = (keyAuthz: string): string => {
  const hasher = crypto.createHash("sha256");
  hasher.update(keyAuthz);
  const hash = hasher.digest();

  return base64url.encode(hash);
};

/// Helper: Normalize JWS protected input.
const jwsInputPart = (value: any): string => {
  if (!Buffer.isBuffer(value)) {
    if (typeof value !== "string") {
      value = JSON.stringify(value) || "";
    }
    value = new Buffer(value);
  }
  return base64url.encode(value);
};

/// Signed JWS object.
export interface SignedJws {
  header: {
    alg: JwsAlg;
    jwk: RSA_JWK;
  };
  protected: string;
  payload: string;
  signature: string;
}

/// Partial JWS object that contains just content.
export interface JwsContent {
  protected: object;
  payload: object;
}

/// Create a signed JWS object from an object using RS256.
/// This function is useful during account key roll-over.
export const jwsRS256 = (
  content: JwsContent,
  privateKey: string,
  publicKey: string
): SignedJws => {
  const protHeader = jwsInputPart(content.protected);
  const payload = jwsInputPart(content.payload);

  const signer = crypto.createSign("RSA-SHA256");
  signer.update(protHeader + "." + payload);
  const signature = signer.sign(privateKey);

  return {
    header: {
      alg: "RS256",
      jwk: jwk(publicKey)
    },
    protected: protHeader,
    payload,
    signature: base64url.encode(signature)
  };
};

/// Helper: Wrap a request callback to handle JSON.
/// We cannot use the request `json` flag, because it annoyingly doesn't deal
/// well with only one side sending JSON. Instead, rely on Content-Type.
const jsonContentTypes = ["application/json", "application/problem+json"];
const wrapRequestCallback = (callback: ResponseCallback): ResponseCallback => {
  return (err, res) => {
    const contentType = res && res.headers["content-type"];
    if (contentType && jsonContentTypes.indexOf(contentType) !== -1) {
      try {
        res.body = JSON.parse(res.body.toString());
      } catch (e) {
        err = e;
      }
    }
    callback(err, res);
  };
};

/// Helper: Wrap a request callback to handle the nonce header.
const wrapRequestMethodCallback = (
  client: Client,
  callback: ResponseCallback
): ResponseCallback => {
  return (err, res) => {
    if (res) {
      const nonce = res.headers["replay-nonce"];
      if (typeof nonce === "string") {
        client.nonce = nonce;
      }
    }
    callback(err, res);
  };
};

/// Parameters for `get`.
export interface GetParams {
  /// Optional extra headers.
  headers?: object;
}

/// Make a GET API request.
export const get = (
  url: string,
  params: GetParams,
  callback: ResponseCallback
): Request => {
  return request(
    {
      method: "GET",
      url,
      encoding: null,
      headers: params.headers
    },
    wrapRequestCallback(callback)
  );
};

/// Parameters for `post`.
export interface PostParams {
  /// The account RSA private key in PEM format.
  privateKey: string;
  /// The account RSA public key in PEM format.
  publicKey: string;
  /// The nonce from an earlier request.
  nonce: string;
  /// Optional extra headers.
  headers?: object;
}

/// Make a POST API request.
export const post = (
  url: string,
  body: object,
  params: PostParams,
  callback: ResponseCallback
): Request => {
  const signed = jwsRS256(
    {
      protected: { nonce: params.nonce },
      payload: body
    },
    params.privateKey,
    params.publicKey
  );

  return request(
    {
      method: "POST",
      url,
      encoding: null,
      headers: Object.assign(
        {
          "Content-Type": "application/json"
        },
        params.headers
      ),
      body: new Buffer(JSON.stringify(signed))
    },
    wrapRequestCallback(callback)
  );
};

/// Parameters for `poll`.
export interface PollParams {
  /// Optional extra headers.
  headers?: object;
  /// Optional function invoked on every response.
  onResponse?: (response: Response) => void;
}

/// Handle returned by `poll`.
export interface PollHandle {
  /// Stop polling. (Never fails.)
  destroy: () => void;
}

/// Make GET API requests until the server no longer responsed with `202` and
/// `Retry-After`.
export const poll = (
  url: string,
  params: PollParams,
  callback: ResponseCallback
): PollHandle => {
  let aborted = false;

  // Make one request.
  const one = () => {
    if (aborted) {
      return;
    }

    get(url, params, (err, res) => {
      if (aborted) {
        return;
      }
      if (err) {
        callback(err, res);
        return;
      }

      if (params.onResponse) {
        params.onResponse(res);
        if (aborted) {
          return;
        }
      }

      const retryAfter = res.headers["retry-after"];
      if (res.statusCode === 202 && retryAfter) {
        schedule(retryAfter);
        return;
      }

      callback(null, res);
    });
  };

  // Schedule the next request.
  const schedule = (delayStr: string): void => {
    let delay: number;
    if (/^[0-9]+$/.test(delayStr)) {
      delay = parseFloat(delayStr);
    } else {
      delay = Date.parse(delayStr) - Date.now();
    }

    delay = isFinite(delay) ? Math.max(1000, delay) : 10000;

    setTimeout(one, delay);
  };

  // Start on the next tick.
  process.nextTick(one);

  // Return a handle.
  return {
    destroy() {
      aborted = true;
    }
  };
};

/// Signature of a resource function created by `directory`.
export interface DirectoryResource {
  url: string;
  (body: object, params: PostParams, callback: ResponseCallback): Request;
}

/// Result of `directory`: an object with `post`-like functions.
export interface DirectoryResources {
  [resource: string]: DirectoryResource;
}

/// Callback signature of the `directory` function.
export type DirectoryCallback = (
  error: any,
  result: DirectoryResources
) => void;

/// The main client class.
///
/// This provides simple wrappers for the exports, merging in client default
/// parameters, and rotating the nonce.
export class Client {
  params: Partial<PostParams>;
  nonce?: string;

  /// Create a client instance.
  ///
  /// Additional params are defaults for requests (Usually `privateKey` and
  /// `publicKey`.
  constructor(params: Partial<PostParams>) {
    this.params = params;
    this.nonce = undefined;
  }

  /// Fetch the directory resource.
  ///
  /// This is usually the first thing to do with a client. The result is an
  /// object with `post`-like functions, used to call the resources defined in
  /// the directory.
  directory(url: string, callback: DirectoryCallback): Request {
    const resources: DirectoryResources = {};

    // Create a function for requesting a resource.
    const createResource = (name: string, url: string): DirectoryResource => {
      const resource = (
        body: object,
        params: PostParams,
        callback: ResponseCallback
      ): Request => {
        const bodyWithResource = Object.assign(body, { resource: name });
        return this.post(url, bodyWithResource, params, callback);
      };
      resource.url = url;
      return resource;
    };

    return this.get(url, {}, (err, res) => {
      if (!err && res.statusCode !== 200) {
        err = Error(
          "Could not fetch ACME directory, status code: " + res.statusCode
        );
      }
      if (err) {
        callback(err, resources);
        return;
      }

      // Iterate resources in the directory.
      const resourceMap = res.body;
      for (const name of Object.keys(resourceMap)) {
        const url = resourceMap[name];

        // Build resource name as camel-case.
        const prop = name.replace(/-([a-z])/g, m => m[1].toUpperCase());

        // Create the resource function.
        resources[prop] = createResource(name, url);
      }

      // Return.
      callback(null, resources);
    });
  }

  /// Make a GET API request.
  get(url: string, params: GetParams, callback: ResponseCallback): Request {
    callback = wrapRequestMethodCallback(this, callback);
    return get(url, params, callback);
  }

  /// Make a POST API request.
  post(
    url: string,
    body: object,
    params: PostParams,
    callback: ResponseCallback
  ): Request {
    const combinedParams = Object.assign(
      {},
      this.params,
      { nonce: this.nonce },
      params
    );

    callback = wrapRequestMethodCallback(this, callback);
    return post(url, body, combinedParams, callback);
  }

  /// Make GET API requests until the server no longer responsed with `202` and
  /// `Retry-After`.
  poll(
    url: string,
    params: PollParams,
    callback: ResponseCallback
  ): PollHandle {
    callback = wrapRequestMethodCallback(this, callback);
    return poll(url, params, callback);
  }
}

/// Client interface extension that adds directory resources.
interface ClientExtResources {
  /// Resources the ACME service listed in its directory.
  resources: DirectoryResources;
}

/// A client that includes directory resources.
type ClientWithResources = Client & ClientExtResources;

/// Signature of the `createClient` callback.
type CreateClientCallback = (error: any, client: ClientWithResources) => void;

/// Create a client instance, and fetch the directory.
///
/// The `url` parameter must be a URL to the directory resource.
///
/// Additional params are defaults for requests (Usually `privateKey` and
/// `publicKey`.
export const createClient = (
  url: string,
  params: Partial<PostParams>,
  callback: CreateClientCallback
): void => {
  const client = new Client(params);
  client.directory(url, (err, resources) => {
    callback(err, Object.assign(client, { resources }));
  });
};

/// Production URL of Let's Encrypt's directory resource.
export const LETSENCRYPT_URL = "https://acme-v01.api.letsencrypt.org/directory";

/// Staging URL of Let's Encrypt's directory resource.
export const LETSENCRYPT_STAGING_URL =
  "https://acme-staging.api.letsencrypt.org/directory";
