import base64url from "base64url";
import crypto, { KeyLike, KeyObject } from "crypto";
import pemjwk, { RSA_JWK } from "pem-jwk";

/** Re-export of the `base64url` module. */
export const base64 = base64url;

/** Content-Type for a signed body. */
export const CONTENT_TYPE_JOSE_JSON = "application/jose+json";

/** Content-Type for an ACME error response. */
export const CONTENT_TYPE_PROBLEM_JSON = "application/problem+json";

/** Namespace of ACME errors. */
export const ERROR_NS = "urn:ietf:params:acme:error";

/** The request specified an account that does not exist. */
export const ERROR_ACCOUNT_DOES_NOT_EXIST = `${ERROR_NS}:accountDoesNotExist`;

/**
 * The request specified a certificate to be revoked that has already been
 * revoked.
 */
export const ERROR_ALREADY_REVOKED = `${ERROR_NS}:alreadyRevoked`;

/** The CSR is unacceptable (e.g., due to a short key.) */
export const ERROR_BAD_CSR = `${ERROR_NS}:badCSR`;

/**
 * The client sent an unacceptable anti-replay nonce.
 *
 * Rawacme will automatically handle this error.
 */
export const ERROR_BAD_NONCE = `${ERROR_NS}:badNonce`;

/** The JWS was signed by a public key the server does not support. */
export const ERROR_BAD_PUBLIC_KEY = `${ERROR_NS}:badPublicKey`;

/** The revocation reason provided is not allowed by the server. */
export const ERROR_BAD_REVOCATION_REASON = `${ERROR_NS}:badRevocationReason`;

/** The JWS was signed with an algorithm the server does not support. */
export const ERROR_BAD_SIGNATURE_ALGORITHM = `${ERROR_NS}:badSignatureAlgorithm`;

/**
 * Certification Authority Authorization (CAA) records forbid the CA from
 * issuing a certificate.
 */
export const ERROR_CAA = `${ERROR_NS}:caa`;

/** Specific error conditions are indicated in the "subproblems" array */
export const ERROR_COMPOUND = `${ERROR_NS}:compound`;

/** The server could not connect to validation target */
export const ERROR_CONNECTION = `${ERROR_NS}:connection`;

/** There was a problem with a DNS query during identifier validation */
export const ERROR_DNS = `${ERROR_NS}:dns`;

/** The request must include a value for the "externalAccountBinding" field */
export const ERROR_EXTERNAL_ACCOUNT_REQUIRED = `${ERROR_NS}:externalAccountRequired`;

/** Response received didn't match the challenge's requirements */
export const ERROR_INCORRECT_RESPONSE = `${ERROR_NS}:incorrectResponse`;

/** A contact URL for an account was invalid */
export const ERROR_INVALID_CONTACT = `${ERROR_NS}:invalidContact`;

/** The request message was malformed */
export const ERROR_MALFORMED = `${ERROR_NS}:malformed`;

/** The request attempted to finalize an order that is not ready to be finalized */
export const ERROR_ORDER_NOT_READY = `${ERROR_NS}:orderNotReady`;

/** The request exceeds a rate limit */
export const ERROR_RATE_LIMITED = `${ERROR_NS}:rateLimited`;

/** The server will not issue certificates for the identifier */
export const ERROR_REJECTED_IDENTIFIER = `${ERROR_NS}:rejectedIdentifier`;

/** The server experienced an internal error */
export const ERROR_SERVER_INTERNAL = `${ERROR_NS}:serverInternal`;

/** The server received a TLS error during validation */
export const ERROR_TLS = `${ERROR_NS}:tls`;

/** The client lacks sufficient authorization */
export const ERROR_UNAUTHORIZED = `${ERROR_NS}:unauthorized`;

/** A contact URL for an account used an unsupported protocol scheme */
export const ERROR_UNSUPPORTED_CONTACT = `${ERROR_NS}:unsupportedContact`;

/** An identifier is of an unsupported type */
export const ERROR_UNSUPPORTED_IDENTIFIER = `${ERROR_NS}:unsupportedIdentifier`;

/** Visit the "instance" URL and take actions specified there */
export const ERROR_USER_ACTION_REQUIRED = `${ERROR_NS}:userActionRequired`;

/** The types of PEM headers we support. */
export type PemHeader = "RSA PUBLIC KEY" | "RSA PRIVATE KEY" | "CERTIFICATE";

/** Convert any kind of `KeyLike` to a public key `KeyObject`. */
export const toPublicKey = (key: KeyLike): KeyObject => {
  return key instanceof KeyObject && key.type === "public"
    ? key
    : crypto.createPublicKey(key);
};

/** Check the response content type, to see if it is an ACME error. */
export const isErrorResponse = (res: Response): boolean => {
  const type = (res.headers.get("Content-Type") || "")
    .replace(/;.*$/, "")
    .trim();
  return type === CONTENT_TYPE_PROBLEM_JSON;
};

/** Parse the 'Retry-After' header into a delay (ms), or use a default. */
export const parseRetryDelay = (
  res: Response,
  options: { default?: number; minimum?: number } = {},
): number => {
  let delay = NaN;

  const input = res.headers.get("Retry-After");
  if (input) {
    if (/^[0-9]+$/.test(input)) {
      delay = parseFloat(input);
    } else {
      delay = Date.parse(input) - Date.now();
    }
  }

  // Apply a minimum, and apply a default if we couldn't parse.
  return isFinite(delay)
    ? Math.max(options.minimum || 1000, delay)
    : options.default || 10000;
};

/** Convert a DER buffer to a PEM string. */
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

/** Convert a PEM string to a DER buffer. */
export const toDer = (pem: string): Buffer => {
  const base64 = pem
    .split(/[\r\n]+/g)
    .map((line) => line.trim())
    .filter((line) => line)
    .slice(1, -1)
    .join("");
  return Buffer.from(base64, "base64");
};

/** Create a JWK public key object from an RSA public or private key. */
export const jwk = (key: KeyLike): RSA_JWK => {
  const publicKey = toPublicKey(key);
  const pem = publicKey.export({ format: "pem", type: "pkcs1" });
  return pemjwk.pem2jwk(<string>pem);
};

/**
 * Create a JWK SHA-256 thumbprint from an RSA public or private key.
 *
 * This function is useful for responding to challenges.
 */
export const jwkThumbprint = (key: KeyLike): Buffer => {
  const publicKey = toPublicKey(key);
  if (publicKey.asymmetricKeyType !== "rsa") {
    throw Error("Only RSA keys are supported");
  }

  // We must guarantee the order of properties when hashing here.
  const { e, kty, n } = jwk(publicKey);
  const json = `{"e":"${e}","kty":"${kty}","n":"${n}"}`;

  const hasher = crypto.createHash("sha256");
  hasher.update(json);
  return hasher.digest();
};

/**
 * Create a key authorization from a token and RSA public or private key.
 *
 * This function is useful for responding to challenges.
 */
export const keyAuthz = (token: string, key: KeyLike): string => {
  const thumbprint = jwkThumbprint(key);
  return token + "." + base64url.encode(thumbprint);
};

/**
 * Create a base64 SHA-256 of the key authorization.
 *
 * This function is useful for responding to a dns-01 challenge.
 */
export const dnsKeyAuthzHash = (keyAuthz: string): string => {
  const hasher = crypto.createHash("sha256");
  hasher.update(keyAuthz);
  const hash = hasher.digest();

  return base64url.encode(hash);
};

/** Helper: Normalize JWS protected input. */
const jwsInputPart = (value: any): string => {
  if (!Buffer.isBuffer(value)) {
    if (typeof value !== "string") {
      value = JSON.stringify(value) || "";
    }
    value = Buffer.from(value);
  }
  return base64url.encode(value);
};

/** A signed JWS object. */
export interface SignedJws {
  protected: string;
  payload: string;
  signature: string;
}

/**
 * Create a signed JWS object from an object using RS256.
 *
 * This function is used by `request` to sign requests, but can be useful in
 * specific other cases.
 *
 * One example is account key rollover, where an inner JWS is added to the
 * request body. In this case, follow the spec by leaving `nonce` and `kid`
 * undefined, and setting `url` to `client.resources.keyChange.resourceUrl`.
 * You can use the `jwk` function to build the `oldKey` payload field.
 *
 * The `nonce` should only ever be omitted for such inner JWS cases. The JWS
 * used to sign the request body in ACME always requires a nonce.
 *
 * If no `kid` is specified, the `jwk` property is added to the protected
 * header instead. `kid` should be specified for all requests other than
 * `newAccount` and `revokeCert`.
 */
export const jwsRS256 = (params: {
  payload: any;
  privateKey: KeyLike;
  kid?: string;
  url: string;
  nonce?: string;
}): SignedJws => {
  const encProtected = jwsInputPart({
    alg: "RS256",
    kid: params.kid,
    jwk: params.kid ? undefined : jwk(params.privateKey),
    nonce: params.nonce,
    url: params.url,
  });
  const encPayload = jwsInputPart(params.payload);

  const signer = crypto.createSign("RSA-SHA256");
  signer.update(encProtected + "." + encPayload);
  const signature = signer.sign(params.privateKey);

  return {
    protected: encProtected,
    payload: encPayload,
    signature: base64url.encode(signature),
  };
};

/** Parameters for simple, unsigned requests. */
export interface SimpleRequestParams {
  /** Additional headers for the request. */
  headers?: RequestInit["headers"];

  /**
   * Additional `fetch` options.
   *
   * Note that additional headers should be set using the `headers` parameter,
   * not the property inside this object.
   */
  fetchOptions?: RequestInit;
}

/** Parameters for (signed) ACME requests. */
export interface RequestParams extends SimpleRequestParams {
  /**
   * The account RSA private key.
   *
   * This parameter is required, but has an optional type because client
   * defaults can be merged.
   */
  privateKey?: KeyLike;

  /**
   * The key ID matching the private key.
   *
   * In ACME, this is the account URL obtained from `newAccount`. For the
   * `newAccount` request itself, and for a `revokeCert` request, leave this
   * undefined. (You may need to explicitely specify `kid: undefined` in
   * request parameters to override your client defaults.)
   */
  kid?: string;
}

/** Parameters for `request`. */
export interface RequestMethodParams extends RequestParams {
  /**
   * Optional request body. (Payload of the JWS.)
   *
   * Leaving this empty performs a 'POST-as-GET' request.
   */
  body?: object;
}

/** Parameters for `poll`. */
export interface PollMethodParams extends RequestParams {
  /**
   * Function invoked on every response to check if the response is final.
   *
   * Return `true` here to stop polling. The return value of the `poll` method
   * will then be this response.
   *
   * It's also valid to throw from this function (rejects the `poll` promise)
   * or call `abort` on the handle from this function (abandons the `poll`
   * promise).
   */
  checkResponse: (response: Response) => Promise<boolean>;
}

/** Handle returned by `poll`. */
export interface PollHandle extends Promise<Response> {
  /**
   * Stop polling.
   *
   * This can be called at any time, and never fails. If the promise has not
   * yet resolved, it never will.
   */
  abort: () => void;
}

/** Result of `fetchDirectory`. */
export interface Directory {
  /** Directory metadata returned by the ACME server. */
  meta?: DirectoryMeta;

  /** An object with `request`-like functions for each directory resource. */
  resources: DirectoryResources;
}

/** Directory metadata returned by the ACME server. */
export interface DirectoryMeta {
  /** A URL identifying the current terms of service. */
  termsOfService?: string;

  /** URL of the informational website for this ACME server. */
  website?: string;

  /** Hostnames the client may configure in CAA DNS records. */
  caaIdentities?: string[];

  /** Whether `newAccount` requests require `externalAccountBinding` */
  externalAccountRequired?: boolean;
}

/** Signature of a resource function created by `fetchDirectory`. */
export interface DirectoryResource {
  /**
   * Original name of the resource.
   *
   * Stored separately, because the name of the property containing this
   * function is forced camel-case.
   */
  resourceName: string;

  /** URL of the resource. */
  resourceUrl: string;

  /** Request this resource. */
  (params?: RequestParams): Promise<Response>;
}

/**
 * An object with `request`-like functions for each directory resource.
 *
 * Standardized resources usually present in this directory are:
 *
 *  - newNonce
 *  - newAccount
 *  - newOrder
 *  - newAuthz
 *  - revokeCert
 *  - keyChange
 *
 * Notably, `newAuth` is optional in the ACME spec, and its presence depends on
 * server behavior.
 *
 * Because this object is essentially a map, instances have no prototype (ie.
 * do not inherit from `Object`).
 */
export interface DirectoryResources {
  [resource: string]: DirectoryResource;
}

/**
 * The main client class.
 *
 * While this can be constructed directly, it is usually easier to use
 * `createClient` instead, which automates fetching the directory.
 *
 * ACME interactions usually start through calling one of the directory methods
 * through the `resources` property of this class. You will also frequently
 * need to follow `Link` headers or similar, which can be done with the
 * `request` or `poll` methods. Other methods and properties of this class are
 * more low-level, and less frequently used.
 */
export class Client implements Directory {
  /**
   * Default parameters for requests.
   *
   * You can update this at any time. Notably, you'll usually want to set `kid`
   * after a `newAccount` request.
   */
  params: RequestParams;

  /** The last nonce seen. */
  nonce?: string;

  /**
   * Directory metadata returned by the ACME server.
   *
   * When using `createClient`, this is filled for you. Otherwise, see
   * `fetchDirectory` for how to build this.
   */
  meta: DirectoryMeta;

  /**
   * An object with `request`-like functions for each directory resource.
   *
   * When using `createClient`, this is filled for you. Otherwise, see
   * `fetchDirectory` for how to build this.
   */
  resources: DirectoryResources;

  /**
   * Create a client instance.
   *
   * Default parameters for requests can be provided.
   */
  constructor(params: RequestParams = {}) {
    this.params = params;
    this.nonce = undefined;
    this.meta = {};
    this.resources = Object.create(null);
  }

  /**
   * Request a resource by full URL.
   *
   * This is usually called with a URL from a `Link` header or similar.
   */
  async request(
    url: string,
    params: RequestMethodParams = {},
  ): Promise<Response> {
    const privateKey = params.privateKey || this.params.privateKey;
    if (!privateKey) {
      throw TypeError("The privateKey parameter is required");
    }

    // Get a nonce if needed.
    if (!this.nonce) {
      this.nonce = await this.fetchNonce();
    }

    // Grab and invalidate the nonce.
    const nonce = this.nonce;
    this.nonce = undefined;

    // Create the JWS body.
    const signed = jwsRS256({
      payload: params.body || "",
      privateKey,
      // Make sure the request can override defaults.
      kid: "kid" in params ? params.kid : this.params.kid,
      url,
      nonce,
    });

    // Make the request.
    const res = await fetch(url, {
      ...this.params.fetchOptions,
      ...params.fetchOptions,
      method: "POST",
      headers: {
        ...this.params.headers,
        ...params.headers,
        "Content-Type": CONTENT_TYPE_JOSE_JSON,
      },
      body: JSON.stringify(signed),
    });

    // Extract the next nonce.
    const nextNonce = res.headers.get("Replay-Nonce");
    if (nextNonce) {
      this.nonce = nextNonce;
    }

    // Check if we need to retry because of a bad nonce.
    if (res.status === 400 && isErrorResponse(res)) {
      const body: any = await res.clone().json();
      if (body?.type === ERROR_BAD_NONCE) {
        return this.request(url, params);
      }
    }

    return res;
  }

  /**
   * Poll a resource by full URL.
   *
   * This is usually called with a URL from a `Link` header or similar. The URL
   * is requested (with POST-as-GET requests) until the `checkResponse`
   * function returns `true`.
   *
   * Polling can be aborted by calling `abort` on the returned promise.
   */
  poll(url: string, params: PollMethodParams): PollHandle {
    let aborted = false;

    const handle: Promise<Response> = new Promise((resolve, reject) => {
      // Make one request.
      const one = async () => {
        // Check if `abort` was called, especially after a retry delay.
        if (aborted) {
          return;
        }

        // Make the request.
        let res: Response;
        try {
          res = await this.request(url, params);
          if (aborted) {
            return;
          }
        } catch (err) {
          if (!aborted) {
            reject(err);
          }
          return;
        }

        // Check if this is the final response.
        try {
          if (await params.checkResponse(res)) {
            return resolve(res);
          }
        } catch (err) {
          return reject(err);
        }

        // The callback may call `abort`.
        if (aborted) {
          return;
        }

        // Make another request after the delay.
        setTimeout(one, parseRetryDelay(res));
      };

      // Start now.
      one();
    });

    // Return a handle.
    return Object.assign(handle, {
      abort() {
        aborted = true;
      },
    });
  }

  /**
   * Fetch the directory resource.
   *
   * When using `createClient`, this is done for you, but otherwise probably
   * the first thing you want to do with a client.
   *
   * `createClient` also sets the `meta` and `resources` properties on the
   * client to the return value of this method.
   */
  async fetchDirectory(
    url: string,
    params: SimpleRequestParams = {},
  ): Promise<Directory> {
    const res = await fetch(url, {
      ...this.params.fetchOptions,
      ...params.fetchOptions,
      method: "GET",
      headers: {
        ...this.params.headers,
        ...params.headers,
      },
    });
    if (res.status !== 200) {
      throw Error("Could not fetch ACME directory, status code: " + res.status);
    }

    const resourceMap: any = await res.json();

    // Extract metadata.
    let meta: DirectoryMeta | undefined;
    if (typeof resourceMap?.meta === "object") {
      meta = resourceMap.meta;
    }

    // Create resource functions.
    const createResource = (
      resourceName: string,
      resourceUrl: string,
    ): DirectoryResource => {
      const resource = async (
        params: RequestParams = {},
      ): Promise<Response> => {
        return this.request(resourceUrl, params);
      };
      return Object.assign(resource, { resourceName, resourceUrl });
    };

    // Iterate the directory
    const resources: DirectoryResources = Object.create(null);
    for (const resourceName of Object.keys(resourceMap)) {
      const resourceUrl = resourceMap[resourceName];
      if (typeof resourceUrl !== "string") {
        continue;
      }

      // Build resource name as camel-case.
      const prop = resourceName
        // `x-y` => `xY`
        .replace(/[^a-zA-Z0-9]+([a-z])/g, (m) => m[1].toUpperCase())
        // `X-Y` => `XY`
        .replace(/[^a-zA-Z0-9]+/g, "")
        // `0Y` => `Y`
        .replace(/^[0-9]+/g, "");

      // Create the resource function.
      resources[prop] = createResource(resourceName, resourceUrl);
    }

    return { meta, resources };
  }

  /**
   * Fetch a new nonce.
   *
   * This method is called automatically as needed.
   *
   * If no `url` is specified, `resources.newNonce.resourceUrl` is used. If the
   * resource is not found, an error is thrown.
   */
  async fetchNonce(
    url?: string,
    params: SimpleRequestParams = {},
  ): Promise<string> {
    // Default to the `newNonce` url.
    if (!url) {
      const { newNonce } = this.resources;
      if (!newNonce) {
        throw Error(
          "Cannot fetch a new nonce: newNonce resource is not defined",
        );
      }
      url = newNonce.resourceUrl;
    }

    // Make a `HEAD` request, and extract the nonce.
    const res = await fetch(url, {
      ...this.params.fetchOptions,
      ...params.fetchOptions,
      method: "HEAD",
      headers: {
        ...this.params.headers,
        ...params.headers,
      },
    });
    const nonce = res.headers.get("Replay-Nonce");
    if (!nonce) {
      throw Error(
        "Could not fetch a new nonce: Replay-Nonce header missing from response",
      );
    }

    return nonce;
  }
}

/**
 * Create a client instance, and fetch the directory.
 *
 * The `url` parameter must be the full URL to the directory resource.
 *
 * Default parameters can be provided for requests made with the client.
 */
export const createClient = async (
  url: string,
  params: RequestParams = {},
): Promise<Client> => {
  const client = new Client(params);
  return Object.assign(client, await client.fetchDirectory(url));
};

/** Production URL of Let's Encrypt's directory resource. */
export const LETSENCRYPT_URL = "https://acme-v02.api.letsencrypt.org/directory";

/** Staging URL of Let's Encrypt's directory resource. */
export const LETSENCRYPT_STAGING_URL =
  "https://acme-staging-v02.api.letsencrypt.org/directory";
