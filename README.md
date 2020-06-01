
# Python SRP6a

* Compatible With: Python 3

This library implements the SRP (Secure Remote Password protocol) algorithm.
SRP is an authentication method that allows the use of user names and passwords over unencrypted channels without revealing the password to an eavesdropper. SRP also supplies a shared secret at the end of the authentication sequence that can be used to generate encryption keys.

#### Variables

The code uses the variable names defined in RFC 5054:

* N, g: group parameters (prime and generator)
* s: salt
* B, b: server's public and private values
* A, a: client's public and private values
* I: user name (aka "identity")
* P: password
* v: verifier
* k: SRP-6 multiplier

#### Group parameters

The values of N and g used in this protocol must be agreed upon by the two parties in question. They can be set in advance, or the host can supply them to the client.
The group parameters (N, g) are required to have N as a safe prime, a prime of the form N=2q+1, where q is a [Sophie Germain prime](https://en.wikipedia.org/wiki/Sophie_Germain_prime). N must be large enough so that computing discrete logarithms modulo N is infeasible.
g should be a generator modulo N , which means that for any X where 0 < X < N, there exists a value x for which g^x % N == X.
The group parameters are taken from the RFC 5054.

#### Links

[RFC2945](https://tools.ietf.org/html/rfc2945) "The SRP Authentication and Key Exchange System"
[RFC5054](https://tools.ietf.org/html/rfc5054) "Using the Secure Remote Password (SRP) Protocol for TLS Authentication"
