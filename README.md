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

The C++ core and CLI are a milestone 1 prototype. The real ITI catalogue is blocked: stock OpenSSL 3.6.4 cannot decode ICP-Brasil v7's public key algorithm (OID `1.3.6.1.4.1.44588.2.1`). The full bundle is rejected. No production catalogue, graphical application or version 2 package is shipped yet. The legacy script and installer remain unchanged until the replacement is reviewed. See [DESIGN.md](DESIGN.md) and [VERIFICATION.md](VERIFICATION.md).

The CMake target builds `sparky-ca` against Qt 6 Core/Network, KI18n, OpenSSL and libarchive. `certutil` and `pk12util` serve NSS stores. The test suite generates all certificates locally and checks HTTPS, signatures, SHA-512, pinning, expiry, published root revocation, system installation/removal with Debian's actual updater, and actual NSS databases. All build and test work for this branch runs in non-root Docker containers. Never run the integration suite against host stores.

Prototype commands are `groups`, `list`, `list installed`, `install <group>`, `remove <group|all>`, `status`, `profiles`, `update` and `import <file>`. `--data` supplies the package root manifest; `--catalogue` supplies a verified catalogue. `--nss` selects one browser database. The interactive TTY menu is available when no command is given. `update` writes a verified catalogue to `--output`; it does not automatically install it. A1 import prompts through `pk12util` and remains unverified until milestone 4.

Revocation handling currently covers only explicit package root flags. Intermediate revocation is reported as unknown and CRL processing is still required before production use. Browser discovery and NSS adapters are present; the GUI dispatcher, automatic group refresh, privilege helper and translations remain later work.
