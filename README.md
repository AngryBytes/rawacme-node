# rawacme

Rawacme is a ACME (v2) / [Let's Encrypt] client that doesn't abstract away
protocol details, but provides only functions to ease making the ACME API
calls:

- Fetch API-like interface to perform signed POST and POST-as-GET requests.
- Polling method that handles 202 / `Retry-After` responses.
- Automatic nonce handling, with retries.
- ACME directory parsing.

[let's encrypt]: https://letsencrypt.org/

### Example

```js
const rawacme = require('rawacme');

// Create a client for the Let's Encrypt staging environment.
const client = await rawacme.createClient(rawacme.LETSENCRYPT_STAGING_URL, {
  // Account private key, as PEM or KeyObject.
  privateKey: /* ... */
});

// Directory resources are available as methods on `client.resources`.
// For example, to create an account:
const res = await client.resources.newAccount({
  body: {
    termsOfServiceAgreed: true,
    contact: ["mailto:john@example.com"]
  }
});

// Other times, you may need to request a non-directory URL.
// The `request` method does a POST request:
const res = await client.request(url, {
  body: { /* ... */ }
});

// For POST-as-GET requests that can return `202` with `Retry-After`, the
// `poll` method keeps retrying until the response settles.
const res = client.poll(url);
```

All of the above responses are `Response` instances from the Fetch API,
documented at: https://developer.mozilla.org/en-US/docs/Web/API/Response

Also see [./test.js] for more examples.

### Testing

For testing, use Pebble: https://github.com/letsencrypt/pebble

The included [./test.js] script should work as-is when starting Pebble with
`docker-compose up`, as outlined in the README there.

### License

Copyright (C) 2019 Angry Bytes

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
