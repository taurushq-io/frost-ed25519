# FROST-Ed25519

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

**NOTE ANY DEVIATION FROM THE PROTOCOL**

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

**Give examples**

### Testing

### Example usage


## Dependencies 

Our package has a [minimal set](./go.mod) of third-party dependencies,
mainly Valsorda's [edwards25519](https://filippo.io/edwards25519).


## Intellectual property

This code is copyright (c) Taurus SA, 2021, and under **TBD** license.

