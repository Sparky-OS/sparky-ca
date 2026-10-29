# Sparky CA 2: shared core

The C++ core uses Qt 6 Core/Network, OpenSSL and libarchive.
KI18n supplies English source strings for the CLI.
Kirigami, KAuth, the optional KCM and notifications will use the same core in milestone 2.
`sparky-ca` retains its command name and numbered TTY menu.
Explicit subcommands support scripts.
The display dispatcher and desktop integration come with the GUI.

The schema-1 catalogue stores certificate PEM and source filenames.
The core derives subject, issuer, SHA-256 fingerprint, dates, CA constraints, groups and installation eligibility from certificate bytes.
It ignores caller-supplied classification and state.
Package-owned `pins.json` authenticates exact root fingerprints and records published root revocations.
Root self-signatures do not authenticate anchors; their pins do.
Certificates are deduplicated by fingerprint, with a stable source name and deterministic output.
Refresh retains historical entries absent from the latest bundle.

HTTPS enforces peer and hostname verification.
ITI's missing TLS issuer is supplied from a public chain validated against Debian's TLS roots; this chain is separate from national certificate trust.
The ZIP must match ITI's SHA-512 text and pass expansion, filename and entry limits.
Native CA chains must terminate at a pinned root.
Archival verification permits expired dates, old signature strengths and explicit ECC parameter encoding while still checking signatures and chain constraints.
Installation repeats verification with current dates and normal OpenSSL policy.
Expired, revoked and policy-rejected entries remain listed with their installation issue.

The authorized v7 exception uses its exact SHA-256 pin.
A direct E-521 descendant must match v7's issuer name and authority key identifier, use the E-521 signature OID, and match exact certificate bytes from a package-approved SHA-512 bundle.
Embedded bundle provenance allows that check to be repeated on catalogue load.
Its evidence is labelled `transport-integrity-only`, never `signature-verified`.
The explanation states that the computer's crypto libraries cannot use E-521 and programs need their own implementation; with openssl-provider-ed521 installed, the pinned v7 self-signature verifies and these entries are signature-verified like any other.
Installation requires `--allow-e521`.
The current and historical snapshots contain zero such descendants.
A future E-521 source digest requires a reviewed package update; a supplied offline hash cannot authorize it.

System files live in `/usr/local/share/ca-certificates/sparky-ca`.
Debian's `update-ca-certificates` rebuilds the derived bundle.
Firefox uses `.mozilla/firefox/profiles.ini`; Waterfox uses `.waterfox/profiles.ini`.
Only existing NSS profiles are discovered.
Chromium uses `~/.local/share/pki/nssdb`, with an existing `~/.pki/nssdb` taking priority.
`--nss` explicitly selects a database.
Roots get NSS `C,,`; intermediates get `,,` and do not become anchors.
The Chrome group supplies individually verified roots in place of the old PKCS#7 download.

Store manifests record selected groups and owned fingerprints.
Lock files serialize changes; atomic writes preserve catalogue and ownership state.
Shared entries survive removal of one group.
Removal checks owned bytes and preserves unrelated trust.
System and NSS listing parses actual store certificates and exposes issuer, expiry, state and the E-521 note.
Operations stop on external-tool failures; completed entries remain recorded for recovery.
Cross-store rollback is not implemented.

System changes require root, sudo or pkexec in the CLI.
Browser changes remain the invoking user's.
The milestone-2 KAuth helper must accept constrained group IDs and store targets rather than arbitrary privileged paths.
Tests redirect the real system updater and NSS tools to temporary stores in non-root containers.
Host stores and browser profiles are never mounted.

The repository's scheduled refresh, the machine and user timers and signed CRL evaluation are described in "Keeping the listed certificates current" below.
A1 import and the token path with SoftHSM are verified in the packaging milestone.

## KDE certificate manager implementation

The application and Certificates KCM share `CertificateManager`, which uses immutable core catalogue data, KWallet, KNotifications and the gpgsm functions of the core.
Personal operations run as the user.
System group requests go through KAuth; its helper accepts exactly an operation, known group and boolean Ed521 choice.
The helper owns the store paths and requires root-owned package data without symlinks or group/other write permissions.
Clients cannot send paths, URLs, programs, environment or replacement pins to it.

Catalogue schema 1 also accepts explicit `groups` arrays for another PKI.
Group identifiers are unique lower-case ASCII names with digits/hyphens, 1–64 characters.
Omitted groups retain ICP-Brasil's existing classification.
Explicit grouping changes presentation and selection, never pins or verification.
DER/SHA-256 remains the internal certificate identity.
PEM, DER, PKCS#7 and PKCS#12 conversion happens at the input edge.
The current updater is specific to ITI; another country's update source is future adapter work.

NSS imports preserve an existing identical certificate's nickname.
When a chosen root changes its SSL trust, the previous flags are recorded and restored when our last group releases it.
A later unrelated trust change is refused on removal.
Private identities are not treated as owned catalogue certificates.
Token registration has a separate ownership record.
gpgsm has its own ownership record, `sparky-ca-gpgsm.json` in the GnuPG home: the SHA-1 fingerprints of the certificates Sparky CA imported, and the group that brought each.
A certificate gpgsm already held is not recorded, so removal never touches it.
Trust is never written by this program: the roots enter the keybox untrusted, and the trust list changes only through gpgsm's own question, answered by the user.

Passwords may enter KWallet only through explicit user actions.
The import success callback saves an A1/NSS pair only if selected.
Token PIN policy remains with the token and its signing backend.
Notifications follow completed trust changes and the explicit expiry check.
Automatic refresh notifications belong to the later timer milestone.

NSS/Okular and gpgsm retain their measured algorithm boundaries.
The OpenSSL provider verifies Ed521 in the core and, installed as openssl-provider-ed521, in every program that reads OpenSSL's system configuration; it does not make NSS import that key.
The certificates page probes OpenSSL, NSS (certutil) and gpgsm with ITI's v7 root, says what validates v7 where, and shows nothing once all of them do; closing it hides it until that changes.
Public file previews and CA listings are general PKI operations.
ICP-Brasil is the shipped catalogue, and further pinned catalogues require review.

## Keeping the listed certificates current

### In the repository

`.github/workflows/refresh-catalogue.yml` runs daily and by hand.
The `verify` job has read permission only.
It builds the core in a Debian testing container and runs `tools/refresh-catalogue.sh`.
That script runs `sparky-ca update` against ITI's real bundle, which requires verified HTTPS, ITI's SHA-512 and a chain to a pinned root for every certificate.
The result is one of four words in `out/result`: `current`, `changed`, `unpinned` or `failed`.
The job uploads `out/` as an artifact and fails the run for `unpinned` and `failed`.
The `propose` job holds the write permission and never builds or runs the verifier.
For `changed` it commits only `data/catalogue.json` to the branch `catalogue-refresh`, with `tools/catalogue-diff.py` output as the description, and opens or updates one pull request.
For `unpinned` it opens one issue.
`tools/new-roots.py` lists the self-signed certificates in the bundle that no pin covers, with their SHA-256 fingerprints.
A person checks each against ITI's page and adds the pin in a reviewed commit.
No job writes a pin, so a new root such as a v14 is never trusted by automation.
A wrong SHA-512 yields `failed` and no issue, because the file cannot be examined safely.

### On the machine

`sparky-ca auto run` is the one entry point for both timers and for the command line.
Its scope is `system` for root and `user` otherwise.
The system scope refreshes the catalogue, checks revocation and reconciles the system store.
The user scope uses the system scope's results, never the network, and reconciles each browser database that has an ownership manifest.

The selection is the `groups` list in each store's `.sparky-ca.json`.
That list is written only by `install` and `remove`, so the timer cannot choose a group.
Reconciling a store installs the owned groups' valid, eligible entries that are not yet owned, then drops owned entries that are no longer valid.
Without the Ed521 provider, Ed521 entries are counted and reported as needing the user's choice, never installed; with it they are verified entries like any other.
The updater runs only when something changed.
Browser profiles without selected groups are ignored before checking their locks.
A selected profile with a `lock` link is left untouched, including stale links.
The status report lists these routine deferrals in `deferred`, separately from actionable `notices`.
They use journal info priority and do not trigger a desktop notification.

The machine state is the folder `/var/lib/sparky-ca`, owned by root and not writable by others.
`catalogue.json` is the refreshed catalogue.
`revocation.json` holds the CRL answers.
`status.json` holds the last run and is the notification's source.
Readers use a file only if root or the reader owns it, nobody else can write it and no path component is a link.
The refreshed catalogue is loaded through the same verification as the packaged one and replaces it only if it contains every certificate fingerprint the package ships.
A tampered or truncated cache is ignored, never partly used.
The KAuth helper and the application load the catalogue the same way, so a group installed from the application matches what the timer maintains.

### Revocation

A certificate is checked against the CRL at its own distribution points, one verified answer per issuer and URL.
Plain HTTP is allowed for the CRL fetch only, because the object is signed; TLS verification stays on for every HTTPS download.
A CRL is accepted when its issuer name equals the catalogue issuer's subject, its signature verifies with that issuer's key, it is complete (no indirect, partial or user-only scope) and `thisUpdate` and `nextUpdate` surround now.
A revocation is permanent: a failed fetch never turns a known revoked certificate good.
A good answer lasts until the next update of the CRL that gave it.
An Ed521 issuer's CRL is verified only with the Ed521 provider; without it those certificates stay unknown.
Unknown never removes a certificate.

### Reporting

The journal gets one line per event with syslog priorities when run under systemd.
`sparky-ca-notify` runs in the user's session after the user service and reads both status files.
It shows one notification per new run that added, removed or needs attention, and stays silent otherwise.
The user service also starts when the system's `status.json` changes, so the notification follows the root run.
A machine without a desktop has only the journal; the missing notifier is not an error.

### Privilege

The machine timer runs as root with `ProtectSystem=strict` and write access only to the updater's folders and its state folder.
The application changes the machine's switch through a second KAuth action that accepts exactly one boolean and writes one file.
The user switch is a file in the user's own configuration folder.

## Packaging

The package is a native Debian source package: `debian/` sits beside the code and `dpkg-buildpackage` builds it.
The package needs only stock Debian KDE Frameworks, so it installs on every SparkyLinux edition.
Runtime packages the Kirigami application and the System Settings module need are listed as dependencies, because a missing QML module fails only when the window opens.
OpenSC, p11-kit, pcscd, libccid and gpgsm are recommended, and Kleopatra suggested, because a user without a token or Kleopatra needs none of them.
The Ed521 provider ships as its own package, openssl-provider-ed521, which sparky-ca recommends; it verifies only and has not been independently audited.
Debian's openssl has no configuration directory, so the package diverts the link /usr/lib/ssl/openssl.cnf to a file that includes /etc/ssl/openssl.cnf and then adds the provider, only after a self-test; removing it restores the link.
`dh_installsystemd` is told to handle only the timer, so installing never runs the update service.
The postinst enables the machine timer and, for every user, the user timer and path unit; the switch files are never touched.
The message catalogues come from `po/LINGUAS`; the desktop entries and AppStream metadata come from the same files through `msgfmt`.
The copyright file is machine-readable and keeps the 2018 credit of Paweł Pijanowski on the files his work survives in.


## Kleopatra and gpgsm

`gpgsmImport` imports a group's valid, supported certificates and, for each, its issuers up to the root, roots first, and skips a certificate whose chain is not valid.
It lists the keybox first, so a certificate gpgsm already holds is reported as present and never recorded as ours.
`gpgsmRemove` deletes only recorded fingerprints that no remaining group still needs.
`gpgsmStatus` reads the keybox and reports for each recorded root whether the user confirmed it (gpgsm's trust letter `u`), and for each intermediate that it depends on its root.
`gpgsm-confirm` runs `gpgsm --with-validation --list-keys` on each unconfirmed root with the terminal attached, which makes gpgsm ask its question; nothing answers it.
The application shows the feature only if the executable `gpgsm` exists, and an Open in Kleopatra action only if `kleopatra` exists as well, called with `--query` and a checked fingerprint.
Ed521 certificates are not imported, because gpgsm cannot validate them.
The first gpgsm operation of 2.0.1 removes the managed block and record that 2.0.0 wrote into the trust list, and nothing else in that file.
