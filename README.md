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

### Ristretto

In order to minimize the impact of the cofactor in the Edwards 25519 elliptic curve, we represent the curve points with the
[Ristretto](https://ristretto.group/) encoding.
Our implementation is taken from Filippo Valsorda's [branch](https://github.com/gtank/ristretto255/tree/filippo/edwards25519backend)
of George Tankersley's [ristretto255](https://github.com/gtank/ristretto255).
Internally it uses the [edwards25519](https://github.com/FiloSottile/edwards25519) package.

We add a `BytesEd25519()` method on group elements which allows us to recover an Ed25519 compatible encoding of the curve point.
As elements are represented internally by `edwards25519.Point`, we take this point `P` and remove the cofactor by computing `P' = [8^{-1}][8]P`.
The result is the canonical encoding of `P'`.

For clarity, we distinguish the following elements:

- `B` is the base point of the Edwards 25519 elliptic curve
- `G` is the generator of the Ristretto group

The integer `q` is equal to `2**252 + 27742317777372353535851937790883648493` and is the prime order of the Ristretto group `<G>`.

### Keys

The Ed25519 standard defines the private signing key as a 32 byte _seed_ `x`.
Taking the SHA-512 hash of `x` yields two 32 byte strings by splitting the output in two equal halves: `SHA-512(x) = s || prefix`.
The value `s` encodes 32 byte integer, while the `prefix` is used later for deterministic signature generation.
The public key is the canonical representation of the elliptic curve point `A = [s mod q] • B`.

In FROST-Ed25519, a group of `n` parties `P1, ..., Pn` each hold a _Shamir share_ `s_i` of the secret integer `s`.
These shares are represented as integers mod `q`.
Given any set of at least `t+1` distinct shares, it is possible to recover the original full secret key `s mod q`. 
The integer `t` is the _threshold_ of the scheme, and defines the maximum number of parties that could act maliciously (i.e. collaborate to recover the key).

In FROST-Ed25519, the parties obtain their shares of `s` by executing a Distributed Key Generation (DKG) protocol.
In addition to receiving individual shares `s_i`, all parties also obtain the _group key_ `A = [s]•G`, and its associated public shares `{A_i = [s_i]•G}`.

After a successful execution of the DKG protocol, each party `Pi` obtains:

- a secret share `s_i` represented as a [`eddsa.SecretShare`](pkg/eddsa/secret_share.go) struct
- a set of all public shares `{A_i}` stored in [`eddsa.Public`](pkg/eddsa/public.go) struct
- the group key `A` represented as a [`eddsa.PublicKey`](pkg/eddsa/public_key.go), and stored in the `GroupKey` field of [`eddsa.Public`](pkg/eddsa/public.go).
  Calling `PublicKey.ToEd25519()` returns an `ed25519.PublicKey` compatible with the Ed25519 standard.
  
### Signatures

A FROST-Ed25519 signature for a message `M` is defined by a pair `(R,S)` where: 

- The nonce `R` represents a Ristretto group element, computed as `R = [r]•G` for some `r` mod `q`.
- `S` is a scalar derived computed as

```
R = [r]•G
k = SHA-512(R.BytesEd25519() || A.BytesEd25519() || M)
S = (r + k * s) mod q
```

In the original Ed25519 scheme, the nonce `R = [r]•B` is generated deterministically using the `prefix` in the key generation,
and the integer `r` is computed as `r = H( prefix || M )`.
For threshold signing, it is harder to generate nonce in such a deterministic way.
In FROST-Ed25519, the nonce pair `(r,R)` is generated as detailed in the [FROST paper](https://eprint.iacr.org/2020/852.pdf)

For compatibility with Ed25519, `k` is computed by encoding `R` and `A` as their canonical representations in the edwards25519 curve (cofactor-less).

Signatures are represented by the [`eddsa.Signature`](pkg/eddsa/signature.go) type.

### Verification

The verification algorithm takes a public key `A`, the signed message `M`, and its signature `(R,S)`.
It does the following:

- Recompute `k = SHA-512(R.BytesEd25519() || A.BytesEd25519() || M) mod q` 
- Verify the equality `R == [-k]•A + [S]•G`

Manual verification is not necessary in most cases, but is possible by calling `PublicKey.Verify(message []byte, signature *eddsa.Signature)`.

_Note_: the cofactor is no longer an issue here, since we are considering points in the Ristretto group.

### Compatibility with `ed25519`:

The goal of FROST-Ed25519 is to be compatible with the `ed25519` library included in Go.
In particular, the [`frost.PublicKey`](pkg/eddsa/public_key.go) and [`frost.Signature`](pkg/eddsa/signature.go) types can be converted to the `ed25119.PublicKey` and `[]byte` types respectively,
by calling `.ToEd25519()`.

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

groupKey := public.GroupKey
// use the ed25519 library
ed25519.Verify(groupKey.ToEd25519(), message, groupSig.ToEd25519()) // = true

secretShare.ID == id    // = true
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
The cryptographic protocols are defined in [pkg/frost/keygen]() and [pkg/frost/sign]().
They are handled by a [`State`](pkg/state/state.go) object that takes care of storing messages, passing them to the round at the right time, and reporting any error that may have occurred.

Users of this library should only interact with [`State`](pkg/state/state.go) types. 

### Basics

Each party must be assigned a unique numerical [`party.ID`](pkg/frost/party/id.go) (internally represented as an `uint16`).
A set of `party.ID`s is stored as a [`party.IDSlice`](pkg/frost/party/set.go) which wraps a slice and ensures sorting.

Optionally, a `timeout` argument can be provided, to force the protocol to abort if the time duration between two received messages is longer than `timeout`.
If it is set to 0, then there is no limit.

Appropriate [`State`](pkg/state/state.go)s can be created by calling the functions [`frost.NewKeygenState`](pkg/frost/frost.go) or [`frost.NewSignState`](pkg/frost/frost.go).
They both return the following:
- A [`State`](pkg/state/state.go) object used to interact with the protocol
- An `Output` object whose attributes are initialized to `nil`, and populated asynchronously when protocol has successfully completed.
- An `error` indicating whether the state was successfully created.

An example of how to use the  [`State`](pkg/state/state.go) struct can be found in [example/main.go]().

### Keygen

The key generation protocol we implement is as described in the original paper.

Calling [`frost.NewKeygenState`](pkg/frost/frost.go) with the following arguments creates a [`State`](pkg/state/state.go) object that can execute the protocol. 
```go
var (
    partyID     party.ID        // ID of the party initiating the key generation (`ID` type is an alias for `uint16`)
    partyIDs    party.IDSlice   // sorted slice of all party IDs 
    threshold   party.Size      // maximum number of corrupted parties allowed (`threshold`+1 parties required for signing)
    timeout     time.Duration   // maximum time allowed between two messages received. A duration of 0 indicates no timeout
)

state, output, err := frost.NewKeygenState(partyID, partyIDs, threshold, timeout)
```

Once the protocol has finished, the [`output`](pkg/frost/keygen/output.go) contains the following two fields:

- [`Public`](pkg/eddsa/public.go)
  contains the public key shares of all parties that participated in the protocol,
  as well as the group key these define.
- [`SecretKey`](pkg/eddsa/secret_share.go) is the party's share of the group's signing key.

### Sign


```go
var (
        partyIDs    party.IDSlice       // slice of party IDs which will be performing the signing (must be of length at least `threshold`+1)
        secret      *eddsa.SecretShare  // the secret key share obtained from the keygen protocol
        public      *eddsa.Public       // contains the public information including the group key and individual public shares
        message     []byte              // message in bytes to be signed (does not need to be prehashed)
        timeout     time.Duration       // maximum time allowed between two messages received. A duration of 0 indicates no timeout
)

state, output, err := frost.NewSignState(partySet, secret, public, message, timeout)
```

Once the protocol has finished, the [`output`](pkg/frost/sign/output.go) contains a single field for the [`Signature`](pkg/eddsa/signature.go):

The Signature can be verified using Go's included `ed25519` library, by converting the group key and signature to compatible types.
```go
ed25519.Verify(shares.GroupKey.ToEd25519(), message, output.Signature.ToEd25519())
```

or alternatively,


### Transport Layer

If the round was successfully executed, `State.ProcessAll()` returns a slice [`[]*messages.Message`](pkg/messages/messages.go).
It is up to the user of this library to properly route messages between participants.
The ID's of the sender and destination party of a particular [`messages.Message`](pkg/messages/messages.go) can be found in the `From` and `To` field of the embedded [`messages.Header`](pkg/messages/header.go)
on the [`messages.Message`](pkg/messages/messages.go) object.
Users should first check if the message is intended for broadcast by calling `.IsBroadcast()`, since the `To` field is undefined in this case.

```go
var msg messages.Message
data, err := msg.MarshalBinary()
if err != nil {
	// handle marshalling error, but we cannot continue
	return
}
if msg.IsBroadcast() {
	// send data to all parties except ourselves
} else {
	dest := msg.To
	// send data to party with ID dest
}
```

On the reception, the message should be unmarshalled and then given to the `State`:
```go
var data []byte
var msg messages.Message
err := msg.Unmarshal(data)
if err != nil {
	// handle marshalling error, but we cannot continue
	return
}
err = state.HandleMessage(&msg)
if err != nil {
	// May indicate that an error occurred during transport
	// does not mean we should abort necessarily
	return
}
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
We also include the single `ristretto255` file from [PR 41](https://github.com/gtank/ristretto255/pull/41)

## Intellectual property

This code is copyright (c) Taurus SA, 2021, and under Apache 2.0 license.

