# plasma-nm-wireguard
Addition to plasma-nm to allow the use WireGuard VPN.

If you run across this repository and want to try this, feel free. Just be aware that it is definitely still a work in progress. I started writing it for my own use and it is now to a point where I've been using it for a few days but there are things that need fixing.

This requires installation of [network-manager-wireguard](https://github.com/max-moser/network-manager-wireguard) before this will have any effect.

## Guide

### Compilation
To compile you need to get [plasma-nm](https://github.com/KDE/plasma-nm) and clone this project under the 'vpn' directory in that tree, Then edit the file 'plasma-nm/vpn/CMakeLists.txt' and add 'add_subdirectory(plasma-nm-wireguard)' Then run the build process for plasma-nm and there should be a library called 'libplasmanetworkmanagement_wireguardui.so' created in the corresponding directory in the 'build' tree.

If you already have a binary version of plasma-nm installed, you can probably get away with just copying this library to where the rest of the VPN plugin libraries are located (in my case it was '/usr/lib64/qt5/plugins') but your mileage may vary. Then copy plasmanetworkmanagement_wireguardui.desktop to where all the rest of the 'plasmnetworkmanagement_xxx.desktop' files are. In my case this was /usr/share/kservices5.

