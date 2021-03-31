
Wireguard Utilities
===================

This is a helper module for creating configs for WireGuard_ VPN for both the server side and the
client side.

.. _WireGuard: https://wireguard.com


Quick Start
-----------

Setup a WireGuard server::

    from wireguard import Server

    server = Server('myvpnserver.com', '192.168.24.0/24', address='192.168.24.1')

    # Write out the server config to the default location: /etc/wireguard/wg0.conf
    server.config().write()


Create a client within the previously created server::

    peer = server.peer('my-client')

    # Output this peer's config for copying to the peer device
    print(peer.config().local_config)

    # Rewrite the server config file including the newly created peer
    server.config().write()


Create a standalone client::

    from wireguard import Peer

    peer = Peer('my-client', '192.168.24.0/24', address='192.168.24.45')

    # Write out the peer config to the default location: /etc/wireguard/wg0.conf
    peer.config().write()


**Note**: Both the server and peer config are named the same by default. This is because they would
typically be on different machines and would not interfere with one another. Be aware of this when
generating peer configs on a server node, or on any node that has a pre-existing wireguard config
at the default file location.
