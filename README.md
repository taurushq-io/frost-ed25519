# FROST-Ed25519

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A Go implementation of a [FROST](https://eprint.iacr.org/2020/852.pdf)
threshold signature protocol for the Ed25519 signature scheme.

Our FROST protocol is also inspired from that in the IETF
Draft [Threshold Modes in Elliptic Curves ](https://www.ietf.org/id/draft-hallambaker-threshold-05.html).


## Ed25519

Ed25519 is an instance of the EdDSA construction, defined over the Edwards 25519 elliptic curve.
FROST-Ed25519 is compatible with Ed25519, in the sense that public keys follow the same prescribed format,
and that the same verification algorithm can be used.

Specifically, we implement the _PureEdDSA_ variant as detailed in [RFC 8032](https://tools.ietf.org/html/rfc8032)
(as opposed to HashEdDSA/Ed25519ph or ContextEdDSA/Ed25519ctx.).

We denote `B` the base point of the Edwards 25519 elliptic curve.

### Keys

We represent private keys as `eddsa.PrivateKey`, and are incompatible with Ed25519.

Public keys (denoted by `A` or `A_i` to emphasize the party it belongs to) are represented as `eddsa.PublicKey`.
They can be used to represent both a _GroupKey_, or a single party's _Share_ of the _GroupKey_.

An `ed25519.PublicKey` compatible with `ed25519.Verify` can be obtained by calling `.ToEdDSA()` on the public key.

Mathematically, we can think of the private key as a scalar `s`, where `A = [s] B` is the public key.
```
s || prefix = H(x)
A = [s] B
```
### Signatures

Signatures for a message `M` are defined as a pair `(R, S)` where 

- The _Nonce_ `R` represents an elliptic curve point, whose discrete log `r` is unknown (`R = [r] B`).
- `S` is a scalar derived from a private key `s` and is computed as:
```
R = [r] B
k = SHA-512(R || A || M)
S = (r + k * s) mod L
```
    

In FROST-Ed25519, signatures are represented by `eddsa.Signature` and can be converted to a `[]byte` slice compatible with `ed25519.Verify`
by calling `.ToEdDSA()` on it.

In the original Ed25519 scheme, the nonce `R = [r] B` is generated deterministically using the `prefix` in the keygen:
```
r = H( prefix || M )
```

For threshold signing it is much harder to generate nonce in a deterministic way. 
We refer the reader to [FROST](https://eprint.iacr.org/2020/852.pdf) for the procedure used to generate the nonces.

### Verification

The verification algorithm takes a public key `A`, the signed message `M` and the signature `(R,S)`.
It does the following:

- Recompute `k' = SHA-512(R || A || M)` 
- Verify the equality `[8S] B == [8] R + [8k'] A`


## Protocol version implemented

The FROST paper proposes two variants of the protocol. 
We implement the "single-round" version of FROST, rather than the 4-round variant
FROST-Interactive.

The single-round version actually does one "offline" round, followed
by one "online" round, where the offline round does not need the message
and can therefore be precomputed.
For simplicity, we group both steps together and achieve a 2 round protocol that requires less state handling.
We also ignore the role of _signature aggregator_ and instead let the parties broadcast the signature shares to each other to obtain the full signature.

This variant is the one that is proposed for practical implementations,
however it does not have a full security proof, unlike
FROST-Interactive (see [Section
6.2](https://eprint.iacr.org/2020/852.pdf) of the FROST paper).

## Instructions

FROST-Ed25519 implements a round based architecture for both the keygen and sign protocols.
The basic cryptographic protocol are defined in `/pkg/frost/keygen` and `/pkg/frost/sign` and hold as little state as possible.
They are handled by a `State` which takes care of storing messages, passing them to the round at the right time,
and reporting any error that may have occurred.

Users of this library should only interact with `State` types. 

### Basics

Each party must be assigned a unique numeric `party.ID` (internally represented as `uint32`).
Once all IDs have been attributed, each party must generate an appropriate `party.Set` which is 
a structure used to more easily query the participants.

Optionally, a `timeout` can be defined which forces the protocol to abort if the time duration between two received messages is longer than `timeout`.
If it is set to 0, then there is no limit.

Appropriate `State`s can be created by calling the functions `frost.NewKeygenState` or `frost.NewSignState`.
They both return the following:
- A `State` object used to interact with the protocol
- An `Output` object whose attributes are initialized to `nil`, and populated asynchronously when protocol has successfully completed.
- An `error` indicating whether the state was successfully created.
### Managing State

Once a `State` has been created, the protocol is ready to receive and send messages.

```go
package example

import (
	"log"
	"time"

	"github.com/taurusgroup/frost-ed25519/pkg/frost"
	"github.com/taurusgroup/frost-ed25519/pkg/frost/party"
	"github.com/taurusgroup/frost-ed25519/pkg/messages"
	"github.com/taurusgroup/frost-ed25519/pkg/state"
)

func main() {
	set, _ := party.NewSet([]party.ID{1, 2, 42, 8})
	s, output, err := frost.NewState(set, /* other parameters, */ 2*time.Second)
	if err != nil {
		// handle error
	}
	go func() {
		var msgBytesIn, msgBytesOut chan []byte
		// in a different thread, we can handle messages 
		for {
			select {
			case msgBytes := <-msgBytesIn:
				var msg messages.Message
				if err = msg.UnmarshalBinary(&msgBytes); err != nil {
					// We received a message that is badly formed, the sender could try to send again.
					log.Println("failed to unmarshal message", err)
				}
				if err = s.HandleMessage(&msg); err != nil {
					// An error here may not be too bad, it is not necessary to abort.
					log.Println("failed to handle message", err)
					continue
				}

				for msgOut := range s.ProcessAll() {
					bytesOut, err := msgOut.MarshalBinary()
					if err != nil {
						// This should never happen since we created the message.
						// We should probably abort
						log.Panicln("failed to marshal", err)
                    }
					msgBytesOut <- bytesOut
                }
			case <-s.Done():
				// The protocol has finished
				// We can recover the error here too
				err = s.WaitForError()
				return 
			}
		}
	}()

	// Block until the protocol has finished
	err = s.WaitForError()
	if err != nil {
		// the protocol has aborted
	} else {
		// output now contains the protocol output and can be used.
	}
}
```

#### Keygen: `NewKeygenState`

##### Input 

```go
partyID     party.ID      // ID of the party doing the signing (`ID` type is defined as `uint16`)
partySet    *party.Set    // set containing IDs all parties that will receive a secret key share
threshold   party.Size    // maximum number of corrupted parties allows / threshold+1 parties required for signing
timeout     time.Duration // maximum time allowed between two messages received
```
##### Output

```go
// pkg/frost/keygen/output.go
type Output struct {
	Shares    *eddsa.Shares     
	SecretKey *eddsa.SecretShare
}
```
The `Shares` output contains the public key shares of all parties that participated in the protocol.
The GroupKey computed can be obtained by calling `.GroupKey()`.

The `SecretKey` should be safely stored. It contains the secret key share of the full secret key, and the party ID associated to it.

#### Sign `NewSignState`

##### Input

```go
partySet    *party.Set          // set containing all parties that will receive a secret key share
secret      *eddsa.SecretShare  // the secret obtained from a KeyGen protocol
shares      *eddsa.Shares       // public shares of the key generated during a keygen protocol
message     []byte              // message in bytes to be signed (does not need to be prehashed)
timeout     time.Duration       // maximum time allowed between two messages received
```
##### Output

```go
// pkg/frost/keygen/output.go
type Output struct {
    Signature *eddsa.Signature
}
```
The `Signature` is as an ed25519 compatible signature and can be verified as such:

```go
ed25519.Verify(shares.GroupKey().ToEdDSA(), message, output.Signature..ToEdDSA())
// or
output.Signature.Verify(message, shares.GroupKey())
```
### Testing

We include many tests for individual modules, as well as a bigger integration test in `/test`.
There is still some code that lacks coverage, but we are confident that main output produced is correct.

### Example usage

A simple example of how to use this library can be found in `/test/sign_test.go` and `/test/keygen_test.go`

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

