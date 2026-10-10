# Milestone 1 verification: blocked

Measured 2026-10-09/10 in the workspace Docker proxy. The C++ prototype builds and the fixture suite passes, but the real catalogue cannot be accepted. No production trust operation was performed.

## Container fixture results

Image: `photos-digikam-build:4`, ID `sha256:c8787c156b9dd674f0acd83efa7c9b493ee7dafa622cb3acdb76e65e14a5da69`. It reports Debian Forky, Qt 6.11.2 and OpenSSL 3.6.4. Debian packages `libarchive-dev`, `libarchive13t64`, `libnss3-tools` and `libnss3` were downloaded through authenticated Debian APT indexes and extracted into the workspace as UID 1000. NSS version is 3.130, libarchive 3.8.9. No host packages were installed.

With the workspace set to `/K3D/temp/partners/queue/sparky-ca-2`, the build was configured inside the container using:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_PREFIX_PATH=/K3D/temp/partners/queue/sparky-ca-2/scratch/deps/usr \
  -DBUILD_TESTING=ON
cmake --build build -j4
python3 tests/integration.py build/sparky-ca
ctest --test-dir build --output-on-failure
```

The Docker invocation used `--cpus 4 --user 1000:1000`, only the workspace read-write mount, a workspace `HOME` and `TMPDIR`, `LANG=C.UTF-8`, and the extracted tools' `PATH` and `LD_LIBRARY_PATH`. The detailed test script printed **30 checks passed**. CTest reported **1/1 passed**, in 5.00 seconds on the final run. The image did not need a display or smart-card access. Tests use an ephemeral localhost HTTPS server and generated roots. They check exact fingerprints, trust flags, certificate counts, preserved unrelated NSS entries, overlapping group removal, failed-update preservation, and negative verification outcomes. A same-key, same-subject replacement root is also rejected unless its exact certificate fingerprint is pinned.

The first store test found that Debian's updater preserves the old output when the redirected input is empty. The isolated-store adapter now writes an empty output in that case after running the real updater. The suite then passed. A colon in an NSS nickname caused `certutil -D` to interpret it as a token prefix; owned nicknames now use a hyphen, and actual NSS removal passes.

## Real ITI inputs and blocker

Let's Encrypt's published `int-ye1.pem` and `root-ye-by-x2.pem`, fetched over verified HTTPS, both passed `openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt -untrusted root-ye-by-x2.pem`. The fetched ITI bundle and hash used verified HTTPS with this validated chain. TLS verification was never disabled.

`ACcompactado.zip`: 351,321 bytes. SHA-512:

```text
4585a99955607525e475cf22138302fe8ddce6ca8f0926cd1f01809f007d4bcddff5c1070369d29b1de99c0d2eb058ce0deb856bae0189469ba37e09a59d7985
```

This matches ITI's `hashsha512.txt` and the earlier research. The full historical bundle was downloaded too (624,621 bytes); it has not passed the core verifier. Ten public shipped root files match all ten measured SHA-256 pins, including v1/v2 for archival coverage. Matching fingerprints is not a claim of usable cryptographic support.

The core rejected the current bundle at v7. An independent OpenSSL reference check reproduced the rejection:

```sh
openssl x509 -in data/roots/ICP-Brasilv7.crt -out root7.pem
openssl verify -no_check_time -check_ss_sig -CAfile root7.pem ICP-Brasilv7.crt
```

Result: **verification failed**, error 20, with `X509_PUBKEY_get0:decode error`. `openssl x509 -text` shows both signature and public-key algorithm `1.3.6.1.4.1.44588.2.1`, and “Unable to load Public Key”. The bundled and pinned v7 bytes have the identical SHA-256 `5657e70580eb678983f3ed7dfce091d84cae6549389a47fccda8d0e4dc2cf576`. It is not a corrupt or unpinned download.

A verifier/provider supporting this algorithm must be reviewed before the full bundle can be verified. Removing v7, dropping its chains, accepting signatures without verification or silently weakening TLS would violate this brief. No such workaround was added. A real `data/catalogue.json` is deliberately absent. GUI, automation and packaging milestones have not begun. Intermediate CRL state, complete legacy coverage, the production privilege model, complete translations, A1 and token testing remain incomplete.

Sources: [ITI root status page](https://www.gov.br/iti/pt-br/assuntos/repositorio/repositorio-ac-raiz), [Let's Encrypt certificate hierarchy](https://letsencrypt.org/certificates/). Evidence logs live in the workspace `evidence/` directory; fixture scratch and build outputs are removed when this step ends.
