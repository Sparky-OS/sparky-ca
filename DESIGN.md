STATUS: working

## Milestone 1: design and core

The starting branch is `partner/sparky-ca-2`, at c082050. There are no implementation commits from an earlier lane. I read the workspace brief, the 2020 script and locales, the current script, the certificate research, the edition and stereo plans, and the packaging/style and organisation notes. The host stores and browser profiles have not been opened or changed.

### Design

The shared C++ library uses Qt 6 Core/Network, OpenSSL and libarchive. The CLI uses KI18n. Kirigami, KAuth and notifications will consume the same library in milestone 2. The command stays `sparky-ca`; a numbered menu serves a TTY and explicit subcommands serve scripts. The old desktop name stays. The graphical dispatcher will be added with the GUI.

The catalogue is versioned JSON containing certificate PEM bytes, source filenames and group IDs. Subjects, issuers, fingerprints, validity and CA constraints are derived from X.509, never trusted from JSON. A separate package-owned root manifest pins SHA-256 fingerprints and published root revocation state. Root updates require a human-reviewed manifest change. A certificate can belong to several groups (for example Certisign, RFB and SSL). Legacy group aliases include the Chrome root collection; it installs its individually verified roots into NSS rather than handing a PKCS#7 file to the system updater. Expired and revoked entries remain visible. Unknown status must be explicit rather than described as verified good.

Bundle refresh uses HTTPS with peer and hostname verification, checks ITI's SHA-512 text, limits ZIP sizes and rejects unsafe entries, then verifies every CA chain against only the pinned ICP roots. Catalogue verification and current validity checks are repeated before installation. Historical certificate chains can be checked without enforcing their current dates for archival listing; installation must enforce dates and published revocation exclusions. TLS issuer repair uses a separately validated public issuer chain anchored in Debian's trust store. National roots are not used as TLS anchors. No request ignores TLS errors.

System files live in `/usr/local/share/ca-certificates/sparky-ca`, with `update-ca-certificates` rebuilding Debian's derived store. Browser stores are existing Firefox and Waterfox profiles declared in their `profiles.ini`, and Chromium's `~/.local/share/pki/nssdb`, with an existing `~/.pki/nssdb` taking priority. Roots receive NSS `C,,`, intermediates `,,`. Owned filenames and NSS nicknames use fingerprints. Removal operates on owned entries and leaves other trust entries alone. Listing derives issuer, expiry and state from store bytes and identifies owned entries separately.

Only system mutations require privilege: root/sudo/pkexec in the CLI, a constrained KAuth helper in the GUI. Browser operations remain the invoking user's. A package helper must accept group IDs, not arbitrary privileged paths. Tests use explicitly redirected stores and a local HTTPS fixture server inside a non-root Docker container, including the real Debian updater pointed at fixture directories and real NSS tools. They never mount host stores or profiles.

Milestone 3 will add a scheduled repository fetch/verification job whose changed catalogue opens a review PR; it cannot add pins. On user machines the timer remembers explicitly selected groups, refreshes only those groups, adds new intermediates and removes expired/revoked owned entries. It never selects groups or adds roots automatically. Refresh state and ownership need locking and atomic writes; the user can disable the timer. Desktop notifications and the journal report the result. A1 import and PKCS#11 registration use NSS tools, with generated personal certificates and SoftHSM for milestone 4 verification.

### Initial environment measurements

`DOCKER_HOST=unix:///K3D/temp/partners/queue/sparky-ca-2/docker.sock docker version` succeeds. `photos-digikam-build:4` is an existing Debian Forky image with Qt 6.11.2, OpenSSL 3.6.4, CMake, Ninja, g++ and KF6I18n. It lacks NSS tools and libarchive headers. Dependencies are being downloaded and extracted as UID 1000 in the workspace; no host installation is involved. The image's APT sources include an absent `/repo` and a multimedia source, so the first index update returned errors; its Debian index downloaded and signature checks were not disabled. `/K3D` had 55 GB free and `/` 82 GB before this work.

ITI's [root page](https://www.gov.br/iti/pt-br/assuntos/repositorio/repositorio-ac-raiz), read through the web tool on 2026-10-09, was updated 2026-10-05. It explicitly lists v3, v8 and v9 as revoked, and current CRLs dated 2026-10-01 with next update 2026-12-30. This is newer than the 2026-10-02 research snapshot. The SHA-256 pins in that snapshot still require comparison with the actual shipped root bytes. Neither the web page nor same-server hashes alone establish intermediate revocation status.

Next: implement the verification library, catalogue and store adapters, CLI, and meaningful HTTPS/NSS/container tests; commit each working step. GUI, automation, packaging and full translations remain later milestones.
