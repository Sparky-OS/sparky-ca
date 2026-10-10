# Sparky CA 2

Sparky CA manages certificate trust and personal identities in KDE, browsers
and a text console. ICP-Brasil is its first catalogue. The command remains
`sparky-ca`, and the desktop entry keeps its original name.

The Kirigami application and System Settings **Certificates** module share
one C++ core. They list certificate subjects, issuers, expiry and state in the
catalogue, system bundle, browser NSS databases and KDE's CA manager. KDE CA
enable/disable decisions and rejecting per-host rules use KIO and kssld.
System changes request administrator authorization through KAuth.

The catalogue contains 331 distinct certificates, including the retained 2020
Certisign, OAB and Justiça groups. Expired and revoked certificates remain
visible and are excluded from installation. Root trust depends on reviewed
SHA-256 pins. Downloads require verified HTTPS, ITI's SHA-512 and certificate
chain verification. See [DESIGN.md](DESIGN.md).

## Build

Build in an isolated container. The core requires Qt 6 Core/Network, KI18n,
OpenSSL 3 and libarchive. The KDE front additionally requires Qt Quick,
Kirigami, KAuth, KWallet, KNotifications, KIO and KCMUtils. NSS operations need
`certutil`, `pk12util` and `modutil`; token inspection needs OpenSC and the
locally installed PKCS#11 middleware. GnuPG integration uses `gpgsm` and
`gpgconf`. Okular/Poppler development files enable the PDF integration test.

The front requires the prepared KIO public API patch: the installed
`KSslCertificateManager` header and its `allCaCertificates`,
`isCaCertificateEnabled` and `setCaCertificateEnabled` functions. Stock KF6
6.30 does not publish that header. For development against the matching patched
KIO build, pass `SPARKY_CA_KIO_SOURCE` and `SPARKY_CA_KIO_BUILD` to CMake.
Upstream acceptance is pending.

```sh
cmake -S . -B build -G Ninja
cmake --build build -j4
ctest --test-dir build --output-on-failure
```

`-DBUILD_KDE_FRONTENDS=OFF` builds the core and original public CLI command
without the desktop dependencies. The legacy shell installer is preserved for
reference; version 2 packaging is a later milestone. CMake installs the new
fronts, helper policy, KCM, desktop/service-menu metadata and certificate data.
It installs no placeholder locales. Complete pt_BR/pl translations, the Debian
package and automatic catalogue updates are pending.

## Console and files

With a display, `sparky-ca` opens the graphical application. On a console it
keeps the numbered text menu. `--tty` forces the console front, and scripts
remain text commands even when a display exists.

Commands include `list`, `list installed`, `groups`, `install <group>`,
`remove <group|all>`, `status`, `profiles`, `update`, `preview <file>`,
`import <file>`, `tokens [module]`, `register-token <module>`,
`unregister-token`, `gpgsm-trust <group>` and `gpgsm-untrust <group>`.
`--nss` chooses a browser database. Close that browser before making changes.
CLI system operations require root or the user's chosen sudo/pkexec invocation.
`update --output <file>` refreshes a catalogue without installing certificates.

Dolphin's service menu and MIME associations open `.crt`, `.cer`, `.pem`,
`.p7b`, `.pfx` and `.p12`. Public files show a certificate preview; encrypted
personal identities prompt for their passphrase. Preview does not establish
trust or a revocation result.

## Personal identities, Wallet and PDF signing

An A1 PKCS#12 import checks that its private key matches its certificate,
then imports it into the selected NSS profile. Both the PKCS#12 passphrase
and database password can be saved in KDE Wallet **only after explicit opt-in**.
Read and removal actions are explicit. Password files for scripts preserve
spaces and must contain one password in an owner-only file. Import and temporary password files
are private and removed on completion. No claim of audited memory erasure is
made.

Okular reads NSS identities. Select the same NSS directory in its PDF
certificate settings. Generated RSA and ECDSA identities were imported,
listed in Okular and used to sign PDFs; both signatures and their certificate
chains validated. Altering signed document content failed validation.
Browser TLS trust alone does not grant PDF certificate trust. The signing
test explicitly grants the generated root NSS's S/MIME CA trust for the PDF
validation step; it also checks that TLS-only trust leaves the issuer untrusted.
That separate purpose is not automatically granted by group installation.

A3 PINs are never stored here. The token's retry limits and authentication
policy apply. Register the installed p11-kit proxy to expose configured
modules. Removal checks our ownership record and removes our registration,
leaving unrelated NSS certificates and the token itself intact. Vendor
SafeSign/SafeNet middleware belongs on the user's machine through APTus;
it is not mirrored. Physical cards and proprietary middleware have not been
verified. The SoftHSM fixture belongs to the packaging milestone.

GnuPG root trust for Kleopatra is a separate opt-in decision. Only our
managed trustlist block is removed; unrelated entries are preserved.
Kleopatra uses GnuPG's OpenPGP/S/MIME and smart-card interfaces, rather than
browser NSS databases or our PKCS#11 registration.

## Ed521 and store boundaries

`-DBUILD_ED521_PROVIDER=ON` builds the optional public-verification prototype
following Pedro F. Albanese's e521 reference. Read [its README](ed521-provider/README.md)
for licensing, configuration and limitations. Native v7 handling is enabled
only after the provider verifies the exact pinned ITI v7 self-signature.
The default build leaves this unaudited prototype disabled. It cannot sign.

**An OpenSSL provider does not add an algorithm to NSS or GnuPG.** NSS 3.130
rejects Ed521/v7 and Ed448/v6 key types. Browser group installations exclude
these entries while keeping them listed. Gpgsm rejects Ed521 self-signatures,
so its group trust option excludes Ed521 roots. CLI/OpenSSL Ed521 chain
verification works with the configured provider. Okular cannot validate an
Ed521 chain until NSS supports it or Poppler gains a provider-backed backend.
Neither route has been implemented. The real ITI archives contain no
v7-issued descendant certificate; the tested descendants are synthetic.

Intermediate revocation remains unknown until signed CRL/freshness handling
is implemented. Two historical MRE entries fail OpenSSL's current explicit-ECC
policy, and four optional historical VALID entries have missing issuers.
Their archive records and exclusions remain visible in the source index.
See [VERIFICATION.md](VERIFICATION.md) for measured results and limits.

## License and credits

Sparky CA is GPL-3.0-or-later, without warranty. Paweł "pavroo" Pijanowski is
the original author (2018); Daniel Campos Ramos contributed in 2020 and 2026.
The separate ISC Ed521 prototype follows Pedro F. Albanese's work. KDE/Qt,
OpenSSL, NSS, ITI, Poppler/Okular, GnuPG, p11-kit and OpenSC supply the interfaces
and data used here. Upstream contributions are prepared, not yet published.
