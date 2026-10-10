# Sparky CA

This tool downloads and installs PJeOffice CA Certificates.

## Description

Sparky CA is a graphical tool that simplifies the process of downloading and installing CA certificates required for PJeOffice, the Brazilian electronic judicial system. It provides a simple menu-driven interface to select and install the necessary certificates.

## Dependencies

* `ca-certificates`
* `coreutils`
* `grep`
* `sparky-remsu`
* `sparky-xterm` (>= 0.2.0)
* `wget`
* `yad`

## Installation

To install Sparky CA, run the following commands:

```bash
su (or sudo)
./install.sh
```

## Uninstallation

To uninstall Sparky CA, run the following commands:

```bash
su (or sudo)
./install.sh uninstall
```

## Usage

After installation, you can run Sparky CA in two ways:

1.  **From the command line:** Run `sparky-ca` as root.
2.  **From the desktop launcher:** Use the provided desktop launcher.

The application will present a menu with different categories of CA certificates. Select the desired category to download and install the certificates. The certificates will be installed into `/usr/local/share/ca-certificates`, and the system's CA store will be updated automatically.

## Project Structure

*   `bin/sparky-ca`: The main script that provides the graphical interface for downloading and installing the certificates.
*   `install.sh`: The script for installing and uninstalling the tool.
*   `lang/`: Contains localization files for different languages.
*   `share/`: Contains the desktop entry for launching the application from the graphical environment.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

## Version 2 development branch

Milestone 1 supplies a shared C++ core, CLI and verified catalogue of 331 distinct certificates. All current ITI entries and the 2020 Certisign, OAB, Justiça and root-group filenames are retained. Expired and revoked entries remain listed and cannot install by default. The legacy installer remains preserved pending the version 2 packaging review. See [DESIGN.md](DESIGN.md) and [VERIFICATION.md](VERIFICATION.md).

Build dependencies are Qt 6 Core/Network, KI18n, OpenSSL and libarchive; `certutil` and `pk12util` serve NSS. Container tests use generated crypto/HTTPS fixtures, Debian's real updater pointed at isolated stores, and real NSS databases. The unsupported v7 E-521 anchor stays pinned, with an explicit limitation note and `--allow-e521` choice. Unsupported descendants require exact approved source provenance and matching issuer identities; they are not labelled signature-verified. Neither real archive currently contains a v7 intermediate.

Commands are `groups`, `list`, `list installed`, `install <group>`, `remove <group|all>`, `status`, `profiles`, `update` and `import <file>`. `--data` selects package data; `--catalogue` selects a verified catalogue; `--nss` selects one browser database. A numbered TTY menu runs when no command is given. `update --output <file>` writes a verified catalogue and retains historical entries; it does not install it. Package root pins require review. A1 import prompts through `pk12util` and awaits milestone 4 verification.

Intermediate revocation remains explicitly unknown pending signed CRL handling. Two MRE certificates remain archived with signature verification but fail current OpenSSL installation policy because they use explicit ECC parameters. Four additional historical VALID entries have missing issuers and are withheld, with reasons in `data/source-index.json`; none belongs to the current archive or 2020 baseline. The GUI, KAuth helper, timer, repository workflow, complete translations, tokens and Debian package remain later milestones. The CMake install stages only the new binary and data, without placeholder locales.
