Sparky CA
This tool downloads and installs PJeOffice CA Certificates

Copyright (C) 2018 Paweł Pijanowski and others, see copyright file.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Dependencies:
-------------
ca-certificates
coreutils
grep
sparky-remsu
sparky-xterm (>= 0.2.0)
wget
yad

Install:
-------------
su (or sudo) 
./install.sh

Uninstall:
-------------
su (or sudo)
./install.sh uninstall

Usage:
-------------
After installation run `sparky-ca` as root or use the provided desktop
launcher. The application will download selected CA certificates and
install them into `/usr/local/share/ca-certificates`.

Project structure:
-------------
* `bin/sparky-ca` - main installer script
* `install.sh` - helper script for installation and removal
* `lang/` - localization files
* `share/` - desktop entry for graphical launch
