# rawacme

Rawacme is a ACME / [Let's Encrypt] client that doesn't abstract away protocol
details, but provides only functions to ease making the ACME API calls.

 [Let's Encrypt]: https://letsencrypt.org/

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
