
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


Create a client::

    peer = server.new_peer('my-client')

    # Copy this outputted config to the client device
    print(peer.config)

    # Rewrite the server config file including the newly created peer
    server.write_config()
