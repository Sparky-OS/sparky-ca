#!/bin/sh
#
# Installation and uninstallation script for sparky-ca.
#
# Usage:
#   install.sh         - Installs the sparky-ca tool.
#   install.sh uninstall - Uninstalls the sparky-ca tool.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License as
#  published by the Free Software Foundation; either version 2 of the
#  License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA

if [ "$1" = "uninstall" ]; then
	rm -f /usr/bin/sparky-ca
	rm -f /usr/share/applications/sparky-ca.desktop
	rm -rf /usr/share/sparky/sparky-ca
else
	cp bin/* /usr/bin/
	cp share/* /usr/share/applications/
	if [ ! -d /usr/share/sparky/sparky-ca ]; then
		mkdir -p /usr/share/sparky/sparky-ca
	fi
	cp lang/* /usr/share/sparky/sparky-ca/
fi
