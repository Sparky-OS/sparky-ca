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
