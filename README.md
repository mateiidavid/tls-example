## mTLS example in Go

Quick proof of concept to see how the TLS implementation in Go works wrt to
certificates. The example itself is simple:

* Based on a certificate bundle (i.e two CAs, a self-signed trust anchor and an
  issuer CA), and a client and server, observe whether an expired CA still
  allows the mTLS handshake to succeed.
* An HTTPS server is bound by default on port 4000 and accepts incoming
  connections. All successful requests will receive a `204 (No content)` status
  code.
* An HTTPS client connects to the server (by default on port 4000); if request
  is successful, it prints out the HTTP status received.

  Both client and server need to be run with their own leaf certificates and the trust bundle.


### Running

No build scripts have been included. Build and/or run using Go's tooling:

```sh

:; git clone github.com/mateiidavid/tls-example
:; cd tls-example
:; go build -o tls-example

```

The binary has two sub-commands, `server` and `client` which will spawn the
appropriate task. By default, both are configured to read certificates in the
same directory as the binary, however, that can be overwritten. To run, valid
certificates must be provided.

```sh
#
# Generate trust anchor and CA, put them in a bundle.
# Note: CA expires after 1m, make sure to generate the certs within this time.
#
:; step certificate create root.linkerd.cluster.local ca.crt ca.key \
       --profile root-ca --no-password --insecure --not-after 1m 
;: step certificate create identity.linkerd. issuer.crt issuer.key \
       --profile intermediate-ca --not-after 8760h --no-password --insecure \
       --ca ca.crt --ca-key ca.key

#
# Generate client and server certs
# Note: server name is hardcoded (to not overcomplicate things) in the HTTP client
#
:; step certificate create leaf-server.linkerd.cluster.local server-leaf.crt server-leaf.key \
       --profile leaf --not-after 8760h --no-password --insecure \
       --ca issuer.crt --ca-key issuer.key

:; step certificate create leaf-client.linkerd.cluster.local client-leaf.crt client-leaf.key \
       --profile leaf --not-after 8760h --no-password --insecure \
       --ca issuer.crt --ca-key issuer.key

#
# Run
# 
./tls-example server < /dev/null 2>/dev/null &
./tls-example client

```


