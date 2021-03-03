
Wireguard Utilities
===================

This is a helper module for creating configs for WireGuard_ VPN for both the server side and the
client side.

.. _WireGuard: https://wireguard.com


Quick Start
-----------

Setup a WireGuard server::

    from wireguard import WireGuardServer

    server = WireGuardServer('myvpnserver.com', '192.168.24.0/24', address='192.168.24.1')

    # Write out the server config to the default location: /etc/wireguard/wg0.conf
    server.write_config()


Create a client within the previous server::

    peer = server.peer('my-client')

    # Copy this outputted config to the client device
    print(peer.config())

    # Rewrite the server config file including the newly created peer
    server.write_config()


Create a standalone client::

    from wireguard import WireGuardPeer

    peer = WireGuardPeer('my-client', '192.168.24.0/24', address='192.168.24.45')

    # Write out the peer config to the default location: /etc/wireguard/wg0.conf
    peer.write_config()


**Note**: Both the server and peer config are named the same by default. This is because they would
typically be on different machines and would not interfere with one another. Be aware of this when
generating peer configs on a server node, or on any node that has a pre-existing wireguard config
at the default file location.
