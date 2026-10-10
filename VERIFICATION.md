# Core and Ed521 prototype verification

## Milestone 2

The opt-in ISC provider follows Pedro F. Albanese's e521 reference after
the local Go interoperability fixes passed. It provides public PureEd521
verification with empty context, not private operations or audited signing.
No Ed521ph X.509 OID is assumed. The existing application license is unchanged.

Build inside the non-root, four-CPU container described below:

```sh
cmake -S . -B build -G Ninja -DBUILD_ED521_PROVIDER=ON \
  -DCMAKE_PREFIX_PATH=/workspace/scratch/deps/usr
cmake --build build -j4
ctest --test-dir build -V
```

Tests activate the module in temporary OpenSSL configuration files. They
never modify the host configuration or its stores. With the module loaded,
`openssl verify -check_ss_sig` verifies the real ITI v7 self-signature and an
independently generated three-level Ed521 chain. All 132 single-byte signature
mutations, a message mutation, a public-key mutation and an altered intermediate
fail. The synthetic chain fails without the provider. A separate constraint
test rejects ten malformed, noncanonical or small-order SPKIs and confirms
signing/key generation are unavailable. Provider integration passed in 101.70
seconds; the added constraint test passed in 1.02 seconds.

The core enables native Ed521 handling only after OpenSSL actually verifies
the exact pinned ITI v7 self-signature. Ten new checks verify marker removal,
full intermediate signature verification, absence-of-provider failure, altered
signatures, unpinned roots, wrong bundle hashes, provenance handling and exact
isolated-system-store install/remove results. The unchanged 40 native and 15
integrity-fallback checks also pass: CTest 3/3 in 20.36 seconds. The real catalogue
still has 331 entries; v7 is now eligible when this provider is active.

The two ITI archives contain zero v7-issued certificates, so there is no real
v7 descendant vector to claim. Public synthetic fixtures do not use ITI's private
key. Their signatures agree with independent Python and the patched Go code.
Go's full race suite and go vet pass, including the generated-chain checks
(53.075 seconds for the race suite). Secret operations remain variable-time.

Workspace logs: `evidence/e521-chain-go.log`, `evidence/e521-independent.log`,
`evidence/e521-provider.log`, `evidence/e521-provider-constraints.log`, and
`evidence/e521-core-provider.log`. A provider adds OpenSSL signature capability;
it neither changes root pins nor adds Ed521 support to NSS, Java or browsers.
Browser signing and PKI policy conformance are not established by these tests.

## Milestone 1 record

Measured 2026-10-10 through the workspace Docker proxy. The core, CLI and real catalogue are ready for milestone-1 review. This is not a complete production package; signed intermediate CRL processing, KDE integration, automation and packaging remain later work.

## Environment

Image `photos-digikam-build:4`, ID `sha256:c8787c156b9dd674f0acd83efa7c9b493ee7dafa622cb3acdb76e65e14a5da69`: Debian Forky, Qt 6.11.2, OpenSSL 3.6.4, KI18n, CMake and Ninja. Authenticated Debian APT indexes supplied libarchive 3.8.9 and NSS 3.130 packages, extracted into the workspace without installing host packages. All build/test containers used `--cpus 4 --user 1000:1000`, workspace `HOME`/`TMPDIR`, extracted tools' `PATH`/`LD_LIBRARY_PATH`, and the workspace as their only read-write mount. The legacy URL audit additionally mounted the old repository read-only. No display, host store, browser profile or smart-card access was used.

Configure and test inside that container:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_PREFIX_PATH=/K3D/temp/partners/queue/sparky-ca-2/scratch/deps/usr \
  -DBUILD_TESTING=ON
cmake --build build -j4
ctest --test-dir build -V
```

The final run printed **40 native checks** and **15 E-521 checks**, with **CTest 2/2 passed in 15.68 seconds**. Tests compare exact expected fingerprints, counts and NSS trust flags. Negative checks reject altered certificates, incorrect SHA-512, unpinned roots (including same-key replacements), unsafe ZIP entries, missing/untrusted TLS issuers, wrong hostnames, expired/revoked roots and chains, changed NSS ownership, unsupported algorithm impostors, and missing or altered E-521 provenance. The explicit-ECC archival encoding exception still rejects signature tampering and retains normal installation policy. Positive checks exercise Debian's actual updater in redirected stores, real NSS import/list/remove, unrelated trust preservation, shared group retention, Firefox/Waterfox discovery, Chromium's legacy preference, the numbered TTY menu, and byte-stable refresh.

E-521 descendants in the fixture are synthetic and deliberately unsigned. They exercise the authorized integrity exception, not cryptographic E-521 verification. The real public v7 anchor supplies its exact issuer identity and key identifier. Default installation skips those entries and explains the limitation. Explicit choice installs exact bytes into the isolated system store; removal clears them. E-521 browser usability was not verified.

## Real catalogue checks

ITI's current and historical ZIPs were fetched over verified HTTPS with a validated Let's Encrypt YE1/Root YE cross-certificate chain, and matched their published hashes. `data/source-index.json` records original sizes/counts through the assembly evidence and both SHA-512 digests. `tools/build-snapshot.py` checks those source hashes and prepares an assembly; the C++ core verifies the assembly's chains. Four optional historical VALID entries lack an issuer and are explicitly withheld. They do not belong to the current archive or 2020 baseline.

Commands inside the container, after the authenticated originals were fetched:

```sh
python3 tools/build-snapshot.py \
  --current ../../scratch/iti/ACcompactado.zip \
  --current-hash ../../scratch/iti/hashsha512.txt \
  --historical ../../scratch/iti/ACcompactadox.zip \
  --historical-hash ../../scratch/iti/hashsha512x.txt \
  --output ../../scratch/snapshot.zip --index data/source-index.json
build/sparky-ca --data data update --zip ../../scratch/snapshot.zip \
  --hash ../../scratch/snapshot.sha512 --output data/catalogue.json
build/sparky-ca --data data list > ../../scratch/final-list.json
python3 tools/audit-snapshot.py ../../scratch/final-list.json \
  ../../scratch/iti/ACcompactado.zip ../../scratch/iti/ACcompactadox.zip \
  ../../scratch/iti/legacy.zip
```

The independent OpenSSL DER fingerprint audit confirmed every current archive entry, every retained historical entry, and all 14 still-fetchable legacy certificates. It checks all nine non-root legacy filenames and their groups, 12 roots with ICP/Chrome groups, installation exclusions, and exactly one E-521 entry: the v7 root. Zero E-521 intermediates occur in either archive. There are **331 distinct certificates: 189 temporally valid, 141 expired and one explicitly revoked**, with **186 default-installable**. v7 needs choice; two MRE entries fail current explicit-ECC policy. The original expired AC Raiz also matched its separate published HTTPS download byte-for-byte. v3's new archival pin is always revoked.

The CLI's default live HTTPS refresh succeeded on the Debian image using packaged TLS issuer repair. `cmp data/catalogue.json ../../scratch/live-refresh.json` returned zero, confirming no historical loss or noisy filename/order change. The final offline current-only refresh likewise reproduced identical catalogue bytes.

`DESTDIR=/K3D/temp/partners/queue/sparky-ca-2/scratch/stage cmake --install build` staged the binary under `/usr/bin` and data under `/usr/share/sparky-ca`. The staged executable's listing matched the build-tree listing byte-for-byte. The stage contained no `lang` directory or placeholder locales. This is a CMake stage check, not the milestone-4 Debian package build/install.

## Evidence and remaining limits

Workspace evidence: `evidence/milestone1-final.log`, `evidence/live-refresh-stage.log`, `evidence/legacy-fetch.log`, `evidence/catalogue-source-assembly.log`, `evidence/final-container-results.log`, and `evidence/dependencies.sha256`. Earlier `root-v7-reference.log` records OpenSSL's unsupported-key failure with the exact pinned v7 bytes; the authorized pin/integrity handling supersedes the earlier blocked conclusion. Raw ZIPs, extracted dependencies, stages and build outputs are removed after review evidence capture.

Published root revocations are enforced. Intermediate revocation remains `unknown` until signed CRLs and freshness handling are implemented. No PJeOffice/browser E-521 chain validation, A1 import, PKCS#11 token registration, GUI, KAuth helper, timer, repository workflow, complete translations or version 2 Debian package is claimed. A1 import is wired but awaits the generated certificate test. External-tool failures may leave recorded completed entries; cross-store rollback is not implemented. The four optional historical missing-issuer entries are recorded with source hashes and reasons rather than given a signature exception.
