# FROST-Ed25519

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


A Go implementation of a [FROST](https://eprint.iacr.org/2020/852.pdf)
threshold signature protocol for the Ed25519 signature scheme.

Our FROST-based protocol is also inspired from that in the IETF
Draft [Threshold Modes in Elliptic Curves ](https://www.ietf.org/id/draft-hallambaker-threshold-05.html).

Ed25519 is a instance of the EdDSA construction, which works like this:

(s, A, prefix) = KeyGen():

    x is the secret key
    s || prefix = SHA-512(x)
    A = [s] B

(R, S) = Sign(s, prefix, M):

    r = SHA-512(dom2(F, C) || prefix || PH(M))
    R = [r (mod L)]B
    k = SHA-512(dom2(F, C) || R || A || PH(M))
    S = (r + k * s) mod L

Verif(A, prefix, M, (R,S)):

    (M,R,S)
    k' = SHA512(dom2(F, C) || R || A || PH(M))
    [8S] B == [8] R + [8k'] A

## Protocol version implemented

We implement the "single-round" version of FROST, rather than the 4-round variant
FROST-Interactive.

The single-round version actually does one "offline" round, later followed
by one "online" round, where the offline round does not need the message
and can therefore be precomputed.

This variant is the one that is proposed for practical implementations,
however it does not have a full security proof, unlike
FROST-Interactive (see [Section
6.2](https://eprint.iacr.org/2020/852.pdf)).


### Ed25519 version

We support the original Ed25519, which follows the construction known as
PureEdDSA, as opposed to HashEdDSA/Ed25519ph or ContextEdDSA/Ed25519ctx.

### Deterministic nonce generation

Ed25519 computes nonces 'r' deterministically, which is done in FROST as
follows:

    d_i, e_i random
    D_i = [d_i]B
    E_i = [e_i]B
    l = signing counter
    B = {(D_1, E_1), ..., (D_t, E_t)}
    rho_i = H_1(l, M, B)
    r_i = d_i + e_i • rho_i

    r = ∑ r_i

## Instructions

Give examples

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

