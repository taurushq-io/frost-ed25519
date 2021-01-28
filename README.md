# Threshold Ed25519

This repo implements the [FROST](https://eprint.iacr.org/2020/852.pdf)
protocol adapted to the deterministic Ed25519 signatures scheme.

Our FROST-based protocol is also inspired from that in this [IETF
Draft](https://www.ietf.org/id/draft-hallambaker-threshold-05.html).

## EdDSA Refresher

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

## Variations of FROST

Our initial protocol implements only the first of the two variants.

### "Single-Round" Signing protocol

By "single-round", the authors mean that it is possible to preprocess one round, and perform only one round once the message to sign is known.
Therefore, the protocol should actually be thought of as two rounds.

This variant is the one that is proposed for practical implementations, however no security proof for it is provided.
It is a simplification of the following FROST Interactive protocol.
The main difference is that the value 'rho_i' is generated from a VRF

### FROST Interactive

For FROST-Interactive, 4 rounds are necessary.

## Keygen 

The keygen used is based on the standard Gennaro DKG.
It is not robust however, but any other similar DKG can be used.

## Notes

### PureEdDSA vs EdDSA

The difference between the two schemes is that in the former, the message m to be signed is first hashed.
Our implementation does this, and we use the SHA512 hash over our messages.

### Deterministic Nonce Generation

Unlike ECDSA, Ed25519 was designed to be used without a secure generator.
Instead, a hash function is used to generate the value r.
Securely sampling is hard for lower end devices, whereas they can hashing is usually easier.
The end result is getting a random 'r' that was sampled randomly.
Since this value is supposed to remain secret, signatures where 'r' is generated randomly and those computed deterministically look identical.

Another advantage of deterministic nonces is to prevent accidental reuse, which can risk leaking the secret key.
In FROST, 'r' is computed as such

    d_i, e_i random
    D_i = [d_i]B
    E_i = [e_i]B
    l = signing counter
    B = {(D_1, E_1), ..., (D_t, E_t)}
    rho_i = H_1(l, M, B)
    r_i = d_i + e_i • rho_i

    r = ∑ r_i



### Dependencies 

- [edwards25519](https://filippo.io/edwards25519)
