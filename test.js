#!/usr/bin/env node

const crypto = require("crypto");
const https = require("https");
const rawacme = require(".");

// For testing, use Pebble: https://github.com/letsencrypt/pebble
// This is the default URL where to find the Pebble directory.
const PEBBLE_DIR = "https://localhost:14000/dir";

// To test against Pebble, which uses custom certificates, we create an HTTP
// agent that doesn't verify certificates.
const agent = new https.Agent({
  keepAlive: true,
  rejectUnauthorized: false,
});

// Logging helpers.
const log = (...args) => console.log(...args);
const step = (title) => log(`\n\x1b[1m - ${title}\x1b[0m`);

// Small helper to validate every response.
const checkResponse = async (res) => {
  log(`${res.status} ${res.statusText}`);
  for (const [name, value] of res.headers) {
    log(`${name}: ${value}`);
  }
  log();
  log(await res.text());

  if (!res.ok) {
    throw Error("Request failed");
  }
};

// This example uses a separate `main` function so we can use async/await.
const main = async () => {
  let client;

  // Create the client and fetch the directory.
  {
    // Generate a private key. You'd normally do this only once, then store it
    // somewhere on disk. Note that only RSA keys are supported currently.
    step("Generating a private key...");
    const { privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    log(privateKey.export({ format: "pem", type: "pkcs1" }));

    step("Fetching the directory...");
    client = await rawacme.createClient(PEBBLE_DIR, {
      privateKey,
      fetchOptions: { agent },
    });

    // Dump the directory.
    log("meta:", client.meta);
    for (const resource of Object.values(client.resources)) {
      log(`${resource.resourceName}: ${resource.resourceUrl}`);
    }
  }

  // Create a new account using the first key.
  step("Creating a new account...");
  {
    const res = await client.resources.newAccount({
      body: {
        termsOfServiceAgreed: true,
        contact: ["mailto:john@example.com"],
      },
    });
    await checkResponse(res);

    // When successful, we make further requests with a `kid` specified.
    client.params.kid = res.headers.get("Location");
  }

  // Now you'd normally continue with calling `newAuthz` / `newOrder` to get
  // actual certificates. In this example code, however, we'll demonstrate some
  // other actions that have fewer side-effects, and don't require running
  // additional test services.

  // Verify we can fetch the account object.
  step("Fetching our account object...");
  {
    const res = await client.request(client.params.kid);
    await checkResponse(res);
  }

  // Change keys on the account.
  {
    const oldKey = client.params.privateKey;

    step("Generating a second private key...");
    const { privateKey: newKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    log(newKey.export({ format: "pem", type: "pkcs1" }));

    step("Rotating account keys...");
    const res = await client.resources.keyChange({
      body: rawacme.jwsRS256({
        payload: {
          account: client.params.kid,
          oldKey: rawacme.jwk(oldKey),
        },
        privateKey: newKey,
        url: client.resources.keyChange.resourceUrl,
      }),
    });
    await checkResponse(res);

    // When successful, we make further requests with the new key.
    client.params.privateKey = newKey;
  }

  // Verify we can fetch the account object again.
  step("Fetching our account object again...");
  {
    const res = await client.request(client.params.kid);
    await checkResponse(res);
  }

  step("Done.");
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
