# rawacme

Rawacme is a ACME / [Let's Encrypt] client that doesn't abstract away protocol
details, but provides only functions to ease making the ACME API calls.

[let's encrypt]: https://letsencrypt.org/

### Example

```js
const rawacme = require('rawacme');

/* Create client, request directory */
rawacme.createClient({
    /* ACME directory URL */
    url: rawacme.LETSENCRYPT_STAGING_URL,
    /* For production, use: rawacme.LETSENCRYPT_URL */

    /* Account keypair as PEM strings */
    publicKey: /* ... */,
    privateKey: /* ... */
}, function(err, client) {
    /* Error handling code here */

    /* Directory resources are available as methods.
     * For example, to create a registration: */
    client.newReg({
        /* For directory methods, resource is set for you */
        contact: ['mailto:john@example.com']
    }, function(err, res) {
        /* Error handling code here */

        /* res.body is parsed JSON, or a buffer */
    });

    /* Other times, you need to request a non-directory URL.
     * The client has get and post methods. */
    client.get(url, function(err, res) { /* ... */ });
    client.post(url, body, function(err, res) { /* ... */ });

    /* For GET requests that can return 202 with Retry-After, the poll method
     * keeps retrying until the response settles. */
    client.poll(url, function(err, res) { /* ... */ });
});
```

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
