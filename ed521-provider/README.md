# Ed521 verification provider for OpenSSL 3

This OpenSSL 3 provider verifies Ed521 signatures: EdDSA over the curve E-521, OID `1.3.6.1.4.1.44588.2.1`, the algorithm of ICP-Brasil's root certificate v7 ([DOC-ICP-01.01](https://repositorio.iti.gov.br/instrucoes-normativas/IN2022_22_DOC-ICP-01.01.htm) v6.0, section 2).
It follows **Pedro F. Albanese's e521 reference** (https://github.com/pedroalbanese/e521, upstream `4a89f91`); Pedro is the original implementation's author.
The C port uses his curve constants and point encoding, with the interoperability fixes measured against ITI's real AC Raiz v7: the full 132-octet SHAKE256 challenge and the domain string `"SigEd521" || 0x00 || 0x00`.

ISC keeps his permissive licence, compatible with Apache-2.0 and with the GPL-3.0-or-later application around it.
This subdirectory is ISC; the rest of sparky-ca keeps its own licence and copyrights.

## What it does, and what it never does

- It offers three things, all named `ED521`: a key manager for public keys, PureEd521 verification with an empty context, and a decoder for DER SubjectPublicKeyInfo.
- It has no key generation, no private keys, no signing, no key exchange, no encryption and no TLS signature scheme or group.
  `tests/safety.py` proves this against the complete algorithm inventory of OpenSSL with and without it.
- Every other algorithm stays with the providers that answered it before.
- Points use the complete projective formulas RFC 8032 section 5.2.4 gives for untwisted Edwards curves with non-square d.
  Only public values pass through it, so the variable-time BIGNUM arithmetic is acceptable here; it is not a basis for signing.
- Decoding checks the encoding (RFC 8032 section 5.2.3) and refuses the neutral point; verification and `-pubcheck` also require the key to lie in the subgroup of order L, so small-order and mixed-order keys verify nothing.
- Verification uses the cofactorless equation [S]B = R + [k]A, which RFC 8032 section 5.2.7 allows, and requires S < L.
- It has not been independently audited.

Ed521ph awaits an authoritative numeric OID and parameters; no number is guessed here.

## Installed by the openssl-provider-ed521 package

The package installs the module as `ed521.so` in OpenSSL's module directory and adds it to OpenSSL's system configuration beside the default provider, after checking that the result works; removing it restores the previous configuration.
Its `README.Debian` explains how, since Debian's openssl has no directory for configuration snippets.
`openssl-ed521.cnf` here is that configuration: `/etc/ssl/openssl.cnf` first, then the provider.

To try it without installing, point `OPENSSL_CONF` at a copy of `openssl-ed521.cnf` with a `module = /absolute/path/ed521.so` line under `[ed521_sect]`, then:

```sh
openssl verify -check_ss_sig -CAfile v7.pem v7.pem
```

Accepting a pinned root without `-check_ss_sig` does not prove signature verification.
The provider changes signature capability, not which roots a program trusts.
It does not give NSS, GnuPG, GnuTLS, Java, browsers or Okular Ed521 support.

## Tests

Build and run them inside an isolated container:

```sh
cmake -S ed521-provider -B build-provider -G Ninja
cmake --build build-provider -j4
ctest --test-dir build-provider --output-on-failure
```

- `oracle-specification`: an independent EdDSA reference in Python (`tests/oracle.py`) reproduces every Ed448 and Ed448ph vector of RFC 8032 sections 7.4 and 7.5 through the same generic code that runs Ed521, checks the E-521 parameters of DOC-ICP-01.01, and verifies ITI's v7 self-signature and v7 CRL.
- `provider-vectors`: the provider against ITI's v7 self-signature and CRL, every single-bit mutation of both signatures, and the oracle's vectors in `tests/data/ed521-vectors.json` (wrong domain strings, the truncated 66-octet challenge, S out of range, malformed points, torsion components, weak keys), each also checked without the provider.
- `provider-safety`: the inventory comparison and every refused private-key operation.
- `provider-unchanged-default`: more than 400 certificate, CMS, digest, TLS and listing operations give the same results with and without the provider, apart from lines naming Ed521 and ITI's v7 root.
- `provider-chain`: ITI's v7 root and CRL, and a TEST hierarchy (strict chain, CRL, CMS SignedData, TLS 1.2 and 1.3 through `s_client` and Python's `ssl`).
- `provider-integration` and `provider-constraints`: the earlier synthetic chain and malformed SubjectPublicKeyInfo checks.

The fixtures in `tests/data` are public: ITI's v7 root and CRL, RFC 8032's vectors, and vectors and certificates made from public TEST seeds, which are never anyone's key.
No certificate issued by real v7 was found in ITI's published archives; the TEST hierarchy is not ITI's.
