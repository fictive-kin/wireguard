
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
    server.config.write()


Create a client within the previously created server::

    peer = server.peer('my-client')

    # Output this peer's config for copying to the peer device
    print(peer.config.local_config)

    # Rewrite the server config file including the newly created peer
    server.config.write()


Create a standalone client::

    from wireguard import Peer

    peer = Peer('my-client', '192.168.24.0/24', address='192.168.24.45')

    # Write out the peer config to the default location: /etc/wireguard/wg0.conf
    peer.config.write()


**Note**: Both the server and peer config files are named the same by default. This is because
they would typically be on different machines and would not interfere with one another. Be aware
of this when generating peer configs on a server node, or on any node that has a pre-existing
wireguard config at the default file location.


Other Features
--------------

You can also pass both the address and subnet in a combined way to `Server`::

    # Set the subnet to 192.168.24.0/24 and the server's IP to 192.168.24.51
    server = Server('myvpnserver.com', '192.168.24.51/24')

A custom JSON encoder is also provided: `wireguard.utils.json.JSONEncoder`. This can be used as
the value for `cls` in any call to `json.dumps()`. As a convenience, it is used automatically
by both peers and servers when using the `.json()` method. Any arguments provided are passed
through to `json.dumps()`::

    server.json(sort_keys=True, indent=4)

which will output::

    {
        "address": [
            "192.168.24.51"
        ],
        "allowed_ips": [
            "192.168.24.51/32"
        ],
        "description": "myvpnserver.com",
        "dns": [],
        "endpoint": null,
        "interface": "wg0",
        "keepalive": null,
        "mtu": null,
        "peers": [],
        "post_down": [],
        "post_up": [],
        "pre_down": [],
        "pre_up": [],
        "preshared_key": null,
        "private_key": "+ZNzpdQKgnuFHGtwDn3EzTZB5J8kYis+UMQ4FALSvtI=",
        "public_key": "AvteU+hwrtJW4QvDy/xH+rxXzNHQ33LclcQ646xwmFw=",
        "subnet": [
            "192.168.24.0/24"
        ],
        "table": null
    }

**Note**: If you pass the `cls` argument to the `Peer.json()` method, it will override the use
of the included custom JSON encoder. Therefore, you will have to handle the appropriate objects
within the JSON encoder that is being passed.
