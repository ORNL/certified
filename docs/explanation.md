<!-- This part of the project documentation focuses on an
**understanding-oriented** approach. You'll get a
chance to read about the background of the project,
as well as reasoning about how it was implemented.

> **Note:** Expand this section by considering the
> following points:

- Give context and background on your library
- Explain why you created it
- Provide multiple examples and approaches of how
    to work with it
- Help the reader make connections
- Avoid writing instructions or technical descriptions
    here
-->

# Proofs

Certificates are fundamentally about providing logical proofs
of facts using cryptographic guarantees.

## Definitions:

* authentication - proving that someone is who they claim to be

* authorization  - proving that an action is allowed within the current context

* intent         - proving that an action was intended by the requestor


## Pitfalls of tokens

The number one problem with tokens is that they are not
a reliable method of authentication.  Authentication must
be established when a network communication channel is opened --
for example during the TLS handshake between client and server.
Security conversations become much simpler within mutually
authenticated TLS channels -- since then each party has
established who it is talking to.

Other forms of authentication are subject to third-party
attack.  Tokens are especially vulnerable because
they are exchanged at the application level.
Any server that has observed a token has the potential
to re-use the token -- impersonating the original
sender of the request.

