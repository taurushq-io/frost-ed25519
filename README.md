# FROST-Ed25519

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Go implementation of a [FROST](https://eprint.iacr.org/2020/852.pdf)
threshold signature protocol for the Ed25519 signature scheme.

Our FROST protocol is also inspired from that in the IETF
Draft [Threshold Modes in Elliptic Curves ](https://www.ietf.org/id/draft-hallambaker-threshold-05.html).


### Ed25519

Ed25519 is an instance of the EdDSA construction, defined over the Edwards 25519 elliptic curve.
FROST-Ed25519 is compatible with Ed25519, in the sense that public keys follow the same prescribed format,
and that the same verification algorithm can be used.

See [RFC 8032](https://tools.ietf.org/html/rfc8032) for more information about Ed25519.

We denote `B` the base point of the Edwards 25519 elliptic curve.

#### Keys

We represent private keys as `eddsa.PrivateKey`, and are incompatible with Ed25519.

Public keys (denoted by `A` or `A_i` to emphasize the party it belongs to) are represented as `eddsa.PublicKey`.
They can be used to represent both a _GroupKey_, or a single party's _Share_ of the _GroupKey_.

An `ed25519.PublicKey` compatible with `ed25519.Verify` can be obtained by calling `.ToEdDSA()` on the public key.

Mathematically, we can think of the private key as a scalar `s`, where `A = [s] B` is the public key.

#### Signatures

Signatures for a message `M` are defined as a pair `(R, S)` where 

- The _Nonce_ `R` represents an elliptic curve point, whose discrete log `r` is unknown (`R = [r] B`).

- `S` derived from a private key and is computed as `S = (r + k * s) mod L`, where `k = SHA-512(R || A || M)`.

In FROST-Ed25519, signatures are represented by `eddsa.Signature` and can be converted to a `[]byte` slice compatible with `ed25519.Verify`
by calling `.ToEdDSA()` on it.

#### Verification

The verification algorithm takes a public key `A`, the signed message `M` and the signature `(R,S)`.
It does the following:

- Recompute `k' = SHA-512(R || A || M)` 
- Verify the equality `[8S] B == [8] R + [8k'] A`


## Protocol version implemented

The FROST paper proposes two variants of hte 

We implement the "single-round" version of FROST, rather than the 4-round variant
FROST-Interactive.

The single-round version actually does one "offline" round, followed
by one "online" round, where the offline round does not need the message
and can therefore be precomputed.

This variant is the one that is proposed for practical implementations,
however it does not have a full security proof, unlike
FROST-Interactive (see [Section
6.2](https://eprint.iacr.org/2020/852.pdf) of the FROST paper).


Moreover 

### Ed25519 version

We support the original Ed25519, which follows the construction known as
PureEdDSA, as opposed to HashEdDSA/Ed25519ph or ContextEdDSA/Ed25519ctx.

### Deterministic nonce generation

Unlike the original Ed25519 scheme, our protocol does not generate nonces deterministically.
Instead, we compute them as follows:

    d_i, e_i random
    D_i = [d_i]B
    E_i = [e_i]B
    l = signing counter
    B = {(D_1, E_1), ..., (D_t, E_t)}
    rho_i = H_1(l, M, B)
    r_i = d_i + e_i • rho_i

    r = ∑ r_i

## Instructions



### Testing

### Example usage

## Security

This library was NOT designed to be free of side channels (timing,
memory, oracles, and so on), and due to Go's intrinsic limitations
most likely is not.

This library has yet to be audited and fully vetted for production
usage. Use at your own risk.

Please report any critical security issue to security@taurusgroup.ch.
We encourage you to use our PGP key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEX3G3ARYJKwYBBAHaRw8BAQdA7sQCSqSkAmGylsLRJepXuAZKkcWA+EWRPeGa
22cIXYC0KVRhdXJ1cyBTZWN1cml0eSA8c2VjdXJpdHlAdGF1cnVzZ3JvdXAuY2g+
iJAEExYIADgWIQQ0q1qzH0uLrdBgWQWfaUpuIE2KEAUCX3G3AQIbIwULCQgHAgYV
CgkICwIEFgIDAQIeAQIXgAAKCRCfaUpuIE2KEFn9AP9uAyItJevrH8rV3K4zO25X
7nOI8MQJagBMnGxP+FdF7QD8D3LndQy2AefifK44v8BOKHs0J/hXtkIJTFLu6IzG
MwA=
=QNKX
-----END PGP PUBLIC KEY BLOCK-----
```

Issues that are not critical (not exploitable, DoS, and so on) can be reported as [GitHub Issues](https://github.com/taurusgroup/frost-ed25519/issues).


## Dependencies 

Our package has a [minimal set](./go.mod) of third-party dependencies,
mainly Valsorda's [edwards25519](https://filippo.io/edwards25519).


## Intellectual property

This code is copyright (c) Taurus SA, 2021, and under Apache 2.0 license.

