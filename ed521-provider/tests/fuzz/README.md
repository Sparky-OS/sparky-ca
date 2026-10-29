# Fuzzing the Ed521 provider

Once `openssl-provider-ed521` is installed, every OpenSSL program that parses a certificate with the Ed521 OID runs `decoder.c`, so its input is remote.
These libFuzzer harnesses link the provider's sources, register it as a built-in provider and load it beside OpenSSL's default provider, as the shipped configuration does.

| Harness | Input | Reaches |
| --- | --- | --- |
| `fuzz-spki` | any bytes | OpenSSL's generic DER decoding, ED521 SubjectPublicKeyInfo decoding, `d2i_PUBKEY`, `d2i_X509`, then key parameters, `-pubcheck`, comparison, encoding and the certificate's self-signature |
| `fuzz-verify` | public key (66) ‖ signature (132) ‖ message | `EVP_PKEY_fromdata` and `EVP_DigestVerify`, also with a 131-octet signature and a shortened message |
| `fuzz-verify-v7` | signature (132) ‖ message | the same with ITI's real v7 key |
| `fuzz-x509-verify` | a certificate | `X509_verify_cert` with v7 as the only trust anchor, self-signatures checked, strict rules, a fixed time |

Build and run, inside a container with clang and its libFuzzer runtime:

```sh
tests/fuzz/build.sh OUT
python3 -I tests/fuzz/make-seeds.py SEEDS
OUT/fuzz-spki SEEDS/spki -dict=tests/fuzz/ed521.dict -use_value_profile=1 -max_total_time=1800 -rss_limit_mb=2048 -timeout=1
```

The harnesses keep the references `OSSL_PROVIDER_load` returns: without them LeakSanitizer reports the provider objects as lost, even for OpenSSL's default provider alone.

`corpus/` holds the minimised corpus of each harness.
The normal build compiles every harness with `replay.c` instead of libFuzzer and replays that corpus as the `fuzz-replay-*` tests, so each input found stays a regression test.
