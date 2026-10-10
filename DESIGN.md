# Sparky CA 2: shared core

The C++ core uses Qt 6 Core/Network, OpenSSL and libarchive. KI18n supplies English source strings for the CLI. Kirigami, KAuth, the optional KCM and notifications will use the same core in milestone 2. `sparky-ca` retains its command name and numbered TTY menu. Explicit subcommands support scripts. The display dispatcher and desktop integration come with the GUI.

The schema-1 catalogue stores certificate PEM and source filenames. The core derives subject, issuer, SHA-256 fingerprint, dates, CA constraints, groups and installation eligibility from certificate bytes. It ignores caller-supplied classification and state. Package-owned `pins.json` authenticates exact root fingerprints and records published root revocations. Root self-signatures do not authenticate anchors; their pins do. Certificates are deduplicated by fingerprint, with a stable source name and deterministic output. Refresh retains historical entries absent from the latest bundle.

HTTPS enforces peer and hostname verification. ITI's missing TLS issuer is supplied from a public chain validated against Debian's TLS roots; this chain is separate from national certificate trust. The ZIP must match ITI's SHA-512 text and pass expansion, filename and entry limits. Native CA chains must terminate at a pinned root. Archival verification permits expired dates, old signature strengths and explicit ECC parameter encoding while still checking signatures and chain constraints. Installation repeats verification with current dates and normal OpenSSL policy. Expired, revoked and policy-rejected entries remain listed with their installation issue.

The authorized v7 exception uses its exact SHA-256 pin. A direct E-521 descendant must match v7's issuer name and authority key identifier, use the E-521 signature OID, and match exact certificate bytes from a package-approved SHA-512 bundle. Embedded bundle provenance allows that check to be repeated on catalogue load. Its evidence is labelled `transport-integrity-only`, never `signature-verified`. The explanation states that Linux's crypto libraries cannot use E-521 yet and programs need their own implementation. Installation requires `--allow-e521`. The current and historical snapshots contain zero such descendants. A future E-521 source digest requires a reviewed package update; a supplied offline hash cannot authorize it.

System files live in `/usr/local/share/ca-certificates/sparky-ca`. Debian's `update-ca-certificates` rebuilds the derived bundle. Firefox uses `.mozilla/firefox/profiles.ini`; Waterfox uses `.waterfox/profiles.ini`. Only existing NSS profiles are discovered. Chromium uses `~/.local/share/pki/nssdb`, with an existing `~/.pki/nssdb` taking priority. `--nss` explicitly selects a database. Roots get NSS `C,,`; intermediates get `,,` and do not become anchors. The Chrome group supplies individually verified roots in place of the old PKCS#7 download.

Store manifests record selected groups and owned fingerprints. Lock files serialize changes; atomic writes preserve catalogue and ownership state. Shared entries survive removal of one group. Removal checks owned bytes and preserves unrelated trust. System and NSS listing parses actual store certificates and exposes issuer, expiry, state and the E-521 note. Operations stop on external-tool failures; completed entries remain recorded for recovery. Cross-store rollback is not implemented.

System changes require root, sudo or pkexec in the CLI. Browser changes remain the invoking user's. The milestone-2 KAuth helper must accept constrained group IDs and store targets rather than arbitrary privileged paths. Tests redirect the real system updater and NSS tools to temporary stores in non-root containers. Host stores and browser profiles are never mounted.

Milestone 3 will add the repository's scheduled HTTPS/hash/chain refresh, with catalogue changes proposed for review and no automatic pin changes. A root-owned machine cache and timer will remember the user's selected groups, refresh them, add new intermediates and remove expired or revoked owned entries. It must never choose groups or add roots automatically. The user can disable it; KDE notifications and the journal report results. Signed CRL evaluation and stale-status handling remain to be implemented before production automatic refresh. Intermediate revocation is currently explicit `unknown`; published root exclusions are implemented. A1 import verification and token registration with SoftHSM belong to milestone 4.

## KDE certificate manager implementation

The application and Certificates KCM share `CertificateManager`, which uses
immutable core catalogue data, KIO's CA manager, kssld, KWallet and KNotifications.
Personal operations run as the user. System group requests go through KAuth;
its helper accepts exactly an operation, known group and boolean Ed521 choice.
The helper owns the store paths and requires root-owned package data without
symlinks or group/other write permissions. Clients cannot send paths, URLs,
programs, environment or replacement pins to it.

Catalogue schema 1 also accepts explicit `groups` arrays for another PKI.
Group identifiers are unique lower-case ASCII names with digits/hyphens,
1–64 characters. Omitted groups retain ICP-Brasil's existing classification.
Explicit grouping changes presentation and selection, never pins or verification.
DER/SHA-256 remains the internal certificate identity. PEM, DER, PKCS#7 and
PKCS#12 conversion happens at the input edge. The current updater is specific
to ITI; another country's update source is future adapter work.

NSS imports preserve an existing identical certificate's nickname. When a
chosen root changes its SSL trust, the previous flags are recorded and restored
when our last group releases it. A later unrelated trust change is refused on
removal. Private identities are not treated as owned catalogue certificates.
Token registration has a separate ownership record. GnuPG trust has its own
managed block and group manifest, independent of browser trust.

Passwords may enter KWallet only through explicit user actions. The import
success callback saves an A1/NSS pair only if selected. Token PIN policy remains
with the token and its signing backend. Notifications follow completed trust
changes and the explicit expiry check. Automatic refresh notifications belong
to the later timer milestone.

NSS/Okular and gpgsm retain their measured algorithm boundaries. The OpenSSL
provider can verify Ed521 in the core; it does not make NSS import that key.
Public file previews and CA listings are general PKI operations. ICP-Brasil
is the shipped catalogue, and further pinned catalogues require review.
