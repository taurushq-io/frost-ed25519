# FROST-Ed25519

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Go implementation of a [FROST](https://eprint.iacr.org/2020/852.pdf) threshold signature protocol for the Ed25519 signature scheme.

Our FROST protocol implementation is also inspired from that in the IETF Draft [Threshold Modes in Elliptic Curves ](https://www.ietf.org/id/draft-hallambaker-threshold-05.html).


## Ed25519

Ed25519 is an instance of the EdDSA construction, defined over the Edwards 25519 elliptic curve.
FROST-Ed25519 is compatible with Ed25519, in the sense that public keys follow the same prescribed format,
and that the same verification algorithm can be used.

Specifically, we implement the _PureEdDSA_ variant, as detailed in [RFC 8032](https://tools.ietf.org/html/rfc8032)
(as opposed to HashEdDSA/Ed25519ph or ContextEdDSA/Ed25519ctx.).

We denote `B` the base point of the Edwards 25519 elliptic curve.

### Keys

An Ed25519 private key is a 32 byte _seed_ `x`. 
We compute the SHA-512 hash of `x` and obtain two 32 byte strings by splitting the output in two equal halves: `s || prefix = SHA-512(x)`
The value `s` is encoded as a 32 byte integer, and the `prefix` is used later for deterministic signature generation.
Finally, the public key can be computed as the 32 byte representation of the point `A = [s] • B`.

In FROST-Ed25519, the parties perform a Distributed Key Generation protocol (DKG) (see section [keygen](#keygen) 
in order to obtain a Shamir secret sharing of the integer `s`, and the associated public key `A = [s] • B`
(also referred to as the  _Group Key_).
The parties must agree on a _threshold_ `t` which defines the maximum number of parties that can collaborate,
while still keeping the value of `s` secret. 
This means that at least `t+1` parties are required to perform a signing with key `s`.
We denote by `n >= t+1` the number of parties that participated in the DKG protocol.

A party with ID `i` who participated in a successful execution of the DKG protocol
should obtain at the end an integer `s_i` which defines party `i`'s _share_ of the secret key `s`.
We represent `s_i` by a `SecretShare` object that also contains the ID `i` and the associated group key share `A_i = [s_i]•B`. 
This type is incompatible with the original private key description, since it is not derived from a seed.

The public values generated during the DKG are the individual public key shares `A_j`, for each party with ID `j`.
The group key `A` and its shares `A_i` are represented as `eddsa.PublicKey` objects,
but stored in a `eddsa.Public` structure which ensures consistency between the group key and its shares.

Public keys (denoted by `A` or `A_i` to emphasize the party it belongs to) are represented as `eddsa.PublicKey`.
They can be used to represent both a group key (`GroupKey` object), or a single party's share of the group key (`Share` object).


Mathematically, we can view the private key as a scalar `s`, where `A = [s] B` is the public key.
```
s || prefix = H(x)
A = [s] B
```
### Signatures

Signatures for a message `M` are defined as a pair `(R, S)` where 

- The nonce `R` represents an elliptic curve point, whose discrete logarithm `r` is unknown (`R = [r] B`).
- `S` is a scalar derived from a private key `s` and is computed as:

```
R = [r] B
k = SHA-512(R || A || M)
S = (r + k * s) mod L
```

In FROST-Ed25519, signatures are represented by `eddsa.Signature` and can be converted to a `[]byte` slice compatible with `ed25519.Verify`
by calling `.ToEdDSA()` on it.

In the original Ed25519 scheme, the nonce `R = [r] B` is generated deterministically using the `prefix` in the key generation:

```
r = H( prefix || M )
```

For threshold signing, it is harder to generate nonce in a deterministic way. 
We refer to the [FROST paper](https://eprint.iacr.org/2020/852.pdf) for the procedure used to generate the nonces.

### Verification

The verification algorithm takes a public key `A`, the signed message `M`, and its signature `(R,S)`.
It does the following:

- Recompute `k' = SHA-512(R || A || M)` 
- Verify the equality `[8S] B == [8] R + [8k'] A`

### Compatibility with `ed25519`:

The goal of FROST-Ed25519 is to be compatible with the `ed25519` library included in Go.
In particular, the `frost.PublicKey` and `frost.Signature` types can be converted to the `ed25119.PublicKey` and `[]byte` types respectively,
by calling the method `.ToEd25519()` on objects of these type.

### Example
The following example shows some possible interaction with the types described above:
```go
var (
    id          party.ID                // id of the party
    secretShare *eddsa.SecretShare      // private output of DKG for party id
    public      *eddsa.Public           // public output of DKG
    message     []byte                  // message signed
    groupSig    *eddsa.Signature        // signature produced by sign protocol for message
)

groupKey := public.GroupKey()
// use the ed25519 library
ed25519.Verify(groupKey.ToEd25519(), message, groupSig.ToEd25519()) // = true

secretShare.ID == id    // = true
publicShare, err := public.Share(id) // no error if id was present during keygen 

// shares of the public key correspond to the public output
secretShare.PublicKey().Equal(publicShare) // = true

// Sign message with our own secret key share
privateSig := secretShare.Sign(message)
ed25519.Verify(publicShare.ToEd25519(), message, privateSig.ToEd25519()) // = true
// or also
privateSig.Verify(message, publicShare) // = true
```
## Protocol version implemented

The FROST paper proposes two variants of the protocol. 
We implement the "single-round" version of FROST, rather than the 4-round variant FROST-Interactive.

The single-round version does one "offline" round, followed by one "online" round, where the offline round does not need the message and can therefore be precomputed.
For simplicity, we group both steps together and achieve a 2 round protocol that requires less state handling.
We also ignore the role of _signature aggregator_ and instead let the parties broadcast the signature shares to each other to obtain the full signature.

This variant is the one that is proposed for practical implementations, however it does not have a full security proof, unlike FROST-Interactive (see [Section 6.2](https://eprint.iacr.org/2020/852.pdf) of the FROST paper).

## Instructions

This FROST-Ed25519 implementation includes a round-based architecture for both the key generation and signing protocols.
The cryptographic protocols are defined in pkg/frost/keygen and pkg/frost/sign and hold as little state as possible.
They are handled by a `State` object that takes care of storing messages, passing them to the round at the right time, and reporting any error that may have occurred.

Users of this library should only interact with `State` types. 

### Basics

Each party must be assigned a unique numerical `party.ID` (internally represented as an `uint16`).
Once IDs have been assigned, each party must generate an appropriate `party.Set` object, which is a structure used to more easily query the participants.

Optionally, a `timeout` argument can be provided, to force the protocol to abort if the time duration between two received messages is longer than `timeout`.
If it is set to 0, then there is no limit.

Appropriate `State`s can be created by calling the functions `frost.NewKeygenState` or `frost.NewSignState`.
They both return the following:
- A `State` object used to interact with the protocol
- An `Output` object whose attributes are initialized to `nil`, and populated asynchronously when protocol has successfully completed.
- An `error` indicating whether the state was successfully created.

### Managing a `State`

Once a `State` has been created, the protocol is ready to receive and send messages.

#### Keygen

The key generation protocol we implement is as described in the original paper.

Calling `NewKeygenState()` with the following arguments creates a `State` object that can execute the protocol. 
```go
partyID:     party.ID      // ID of the party performing 
partySet:    *party.Set    // Set containing all party ID of the participants performing the DKG.
threshold:   party.Size    // maximum number of corrupted parties allows / threshold+1 parties required for signing
timeout:     time.Duration // maximum time allowed between two messages received
partyID     party.ID      // ID of the party initiating the key generation (`ID` type is defined as `uint16`)
partySet    *party.Set    // set containing IDs all parties that will receive a secret key share, including the initiative party
threshold   party.Size    // maximum number of corrupted parties allowed (`threshold`+1 parties required for signing)
timeout     time.Duration // maximum time allowed between two messages received
```
The second argument returned by `NewKeygenState()` is the output, and it contains the following fields:

```go
// ./pkg/frost/keygen/output.go
type Output struct {
	Public    *eddsa.Shares
	SecretKey *eddsa.SecretShare
}
```
The `Shares` field contains all public information 
contains the public key shares of all parties that participated in the protocol.
The GroupKey computed can be obtained by calling `.GroupKey()`.

The `SecretKey` should be safely stored. It contains the secret key share of the full secret key, and the party ID associated to it.

#### Sign `NewSignState` <a name="sign"></a>

##### Input

```go
partySet    *party.Set          // set containing all parties that will receive a secret key share
secret      *eddsa.SecretShare  // the secret key share obtained from a KeyGen protocol
public      *eddsa.Public       // contains the public information including the group key and individual public shares
message     []byte              // message in bytes to be signed (does not need to be prehashed)
partySet    *party.Set          // set containing all parties that will receive a secret key share (must be at least `threshold`+1)
secret      *eddsa.SecretShare  // the secret obtained from a KeyGen protocol
shares      *eddsa.Shares       // public shares of the key generated during a keygen protocol
message     []byte              // message to be signed (does not need to be prehashed)
timeout     time.Duration       // maximum time allowed between two messages received
```
##### Output

```go
// pkg/frost/keygen/output.go
type Output struct {
    Signature *eddsa.Signature
}
```
The `Signature` is as an Ed25519 compatible signature and can be verified as follows:

```go
ed25519.Verify(shares.GroupKey().ToEdDSA(), message, output.Signature.ToEdDSA())
```

or alternatively as
```go
output.Signature.Verify(message, shares.GroupKey())
```

### Testing

We include unit tests for individual modules, as well as a bigger integration tests in [test/](test/).
Full test coverage is however not guaranteed.

### Example usage

A simple example of how to use this library can be found in [test/sign_test.go](test/sign_test.go) and [test/keygen_test.go](test/keygen_test.go).

## Security

This library was NOT designed to be free of side channels (timing, memory, oracles, and so on), and due to Go's intrinsic limitations most likely is not.

This library has yet to be audited and fully vetted for production usage.
Use at your own risk.

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

Our package has a [minimal set](./go.mod) of third-party dependencies, mainly Valsorda's [edwards25519](https://filippo.io/edwards25519).


## Intellectual property

This code is copyright (c) Taurus SA, 2021, and under Apache 2.0 license.

