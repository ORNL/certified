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

# Certificates and Signed Tokens

Certificates and signatures (including signed tokens)
are fundamentally about providing logical
proofs of facts using cryptographic guarantees.
Think of signed tokens as like
invitations, tickets, and reservations.

Certificates come in two types: identity documents,
and official seals.
Identity (or end-entity) certificates are like
passports, driver's licenses, and employment records.
Official seals (signing certificates) are like notaries,
bank account access pin-s, and credit cards.
The signing certificate can *do* things, while
the end-entity certificate can *attest* things.

The key distinction between the real world
and the digital one is that whoever holds the
private key on these certificates owns them.
Effectively, your identity documents
have been stolen by anyone, or any piece of software,
who has ever read the corresponding private key.

The use of public-key cryptography ensures you
never need to share your private key anyway.
This is the number one reason hardware key storage
is a good idea -- so that the private key never leaves
the hardware.

You don't change your identity very often, so both
your certificates should remain relatively stable.
You use many different resources for different periods
of time, so your tokens should be fluid -- issued
and revoked often.

In practice, you need both certificates and
signed tokens to get something done.
At the airport, for example, you need both a
passport and a boarding pass.

## Definitions:

* authentication - proving that someone is who they claim to be

* authorization  - proving that an action is allowed within the current context

* intent         - proving that an action was intended by the requestor

## Pitfalls of certificates

The number one problem with certificates is that
they do not record authorization or intent.

Certificates are great for providing authentication.
The web of trust model, for example, can prove
that someone is a friend of a friend.
However, they are not able to provide any advice on
authorization.  For example, it isn't possible to know
whether that friend has been invited to a meeting
based on a certificate.

Some separate communication has to establish intent
and authorization.  We could, for example, write up
a guest list for the meeting.

Certificates basically say "A knows B".  We can extend
them with certificate policies (e.g. an 'admin' policy
number) to say "A knows B and grants them scope 'admin'".
However, a statement of intent like
"A would like a server trusted by C to run X or Y."
is not possible with certificates.
This is where tokens and digital signatures
come into play.


## Pitfalls of tokens

A token can include information of the
form "A authorizes B to do X" or "C intends B to do X".
Both of those statements can be guaranteed by digital
signatures from the principles, A or C, respectively.

The number one problem with tokens is that they are not
a reliable method of authentication.  The token can't
prove that the bearer is B.

That proof of identity (authentication) must
be established when a network communication channel is opened
(for example, during the TLS handshake between client and server).
Security conversations become much simpler within mutually
authenticated TLS channels -- since then each party has
established who it is talking to.

Other forms of authentication are subject to third-party
attack.  Bearer tokens are especially vulnerable because
they are exchanged at the application level.
Any server that has observed a token has the potential
to re-use the token -- impersonating the original
sender of the request.

Note that tokens can be revoked if they include
a URL to be used to check their validity (of if the URL
is understood from context).
For a token naming the principle, e.g. ("A" in "A intends"
or "A authorizes"), another possible solution is to
revoke the principle's certificate, however this stops
all work that A is doing.


# Practical Issues

## Logging Out

Credentials need to be "revoke-able" so that users can
"logout".  Although it is possble to revoke both certificates
and tokens, revoking certificates is less.

## Leaked Credentials

Credentials, e.g. secret keys and tokens get copied into scripts,
which makes the credential no longer trustworthy.  This is usually
a problem with user education.  You wouldn't, for example,
copy your credit card number to a script.

## Activity Logs

Some end entity certificates (identity documents) also
grant special priviledges.  For example, a student ID
card may get you into school football games.  Also,
signing certificates from a ticket machine could be used
to print VIP passes.
Both signing certificates and priviledged ID cards
are targets for theft.

One way to safeguard against unauthorized activity with
long-lived credendials is to present a monthly
audit log of all activity authorized by that credential.
Users should ask for this from facilities that they
regularly interact with, and spend time looking over
their activity logs.

# Visualizing certificates

Apparenty, Firefox displays the contents of certificates
you type into the browser bar if you format them properly.

You can use this to visualize an introduction chain, by
running the following code and then pasting the result
into your browser bar.

```
import urllib.parse
import json

def scrub(c):
    return urllib.parse.quote_plus (
                c.replace("-", "+")
                 .replace("_", "/"))

def main(argv):
    with open(argv[1], "r", encoding="utf-8") as f:
        data = json.load(f)
    c1 = scrub(data["signed_cert"])
    c2 = scrub(data["ca_cert"])
    print(f"about:certificate?cert={c1}&cert={c2}")

if __name__=="__main__":
    import sys
    main(sys.argv)
```
