
import json
import pytest

from wireguard import (
    Peer,
    Server,
)


def test_server_json_dump_ipv4():

    # We're obliged to use `sort_keys=True` here, so that the output will match the
    # pre-built string exactly


    calculated_server = {
            "address": [
                "192.168.0.5"
            ],
            "allowed_ips": [
                "192.168.0.0/24",
                "192.168.0.5/32"
            ],
            "description": "test-server",
            "dns": [],
            "endpoint": None,
            "interface": "wg0",
            "keepalive": None,
            "mtu": None,
            "peers": [],
            "post_down": [],
            "post_up": [],
            "pre_down": [],
            "pre_up": [],
            "preshared_key": None,
            "private_key": "9ZFnCUpTWG3/rOLWXr1Yx5nHY6TawlthxoVl9WsPWJk=",
            "public_key": "clrrtKlXuXnbDXN7nM00fMytLHDzaAGChERA1Pmvqns=",
            "subnet": [
                "192.168.0.0/24"
            ],
            "table": None
        }
    calculated_peer = {
            "address": [
                "192.168.0.52"
            ],
            "allowed_ips": [
                "192.168.0.52/32"
            ],
            "description": "test-peer",
            "dns": [],
            "endpoint": None,
            "interface": "wg0",
            "keepalive": None,
            "mtu": None,
            "peers": [
                {
                    "address": [
                        "192.168.0.5"
                    ],
                    "description": "test-server",
                    "public_key": "clrrtKlXuXnbDXN7nM00fMytLHDzaAGChERA1Pmvqns="
                }
            ],
            "post_down": [],
            "post_up": [],
            "pre_down": [],
            "pre_up": [],
            "preshared_key": None,
            "private_key": "aJ7VaCMQNg0qIQ5Xa3xYJQpF9OZaWk/PQRFYtHxyWVE=",
            "public_key": "ZJMdTDweEMnyoSxa88HWulr3NUtkqhldHHNG/Oup9iM=",
            "table": None
        }
    calculated_server_w_peer = {
            "address": [
                "192.168.0.5"
            ],
            "allowed_ips": [
                "192.168.0.0/24",
                "192.168.0.5/32"
            ],
            "description": "test-server",
            "dns": [],
            "endpoint": None,
            "interface": "wg0",
            "keepalive": None,
            "mtu": None,
            "peers": [
                {
                    "address": [
                        "192.168.0.52"
                    ],
                    "description": "test-peer",
                    "public_key": "ZJMdTDweEMnyoSxa88HWulr3NUtkqhldHHNG/Oup9iM="
                }
            ],
            "post_down": [],
            "post_up": [],
            "pre_down": [],
            "pre_up": [],
            "preshared_key": None,
            "private_key": "9ZFnCUpTWG3/rOLWXr1Yx5nHY6TawlthxoVl9WsPWJk=",
            "public_key": "clrrtKlXuXnbDXN7nM00fMytLHDzaAGChERA1Pmvqns=",
            "subnet": [
                "192.168.0.0/24"
            ],
            "table": None
        }

    server = Server(
        'test-server',
        '192.168.0.5/24',
        private_key='9ZFnCUpTWG3/rOLWXr1Yx5nHY6TawlthxoVl9WsPWJk=',
    )

    assert server.json(sort_keys=True) == json.dumps(calculated_server, sort_keys=True)

    peer = server.peer(
        'test-peer',
        address='192.168.0.52',
        private_key='aJ7VaCMQNg0qIQ5Xa3xYJQpF9OZaWk/PQRFYtHxyWVE=',
    )

    assert peer.json(sort_keys=True) == json.dumps(calculated_peer, sort_keys=True)
    assert server.json(sort_keys=True) == json.dumps(calculated_server_w_peer, sort_keys=True)

    assert peer.json(sort_keys=True) == Peer(**calculated_peer).json(sort_keys=True)
    assert server.json(sort_keys=True) == Server(**calculated_server_w_peer).json(sort_keys=True)


def test_server_json_dump_ipv6():

    # We're obliged to use `sort_keys=True` here, so that the output will match the
    # pre-built string exactly

    calculated_server = {
            "address": [
                "fde2:3a65:ca93:3125::4523:3425"
            ],
            "allowed_ips": [
                "fde2:3a65:ca93:3125::/64",
                "fde2:3a65:ca93:3125::4523:3425/128"
            ],
            "description": "test-server-2",
            "dns": [],
            "endpoint": None,
            "interface": "wg0",
            "keepalive": None,
            "mtu": None,
            "peers": [],
            "post_down": [],
            "post_up": [],
            "pre_down": [],
            "pre_up": [],
            "preshared_key": None,
            "private_key": "3cH3g4JwUdzg+q2Nqwvr9/WVJujWUa9NHy2PiY1jli4=",
            "public_key": "hBo5FSeVkb6WvGzpkitOIJYabLc835XbVjt6a7F0eHQ=",
            "subnet": [
                "fde2:3a65:ca93:3125::/64"
            ],
            "table": None
        }
    calculated_peer = {
            "address": [
                "fde2:3a65:ca93:3125::3425:4523"
            ],
            "allowed_ips": [
                "fde2:3a65:ca93:3125::3425:4523/128"
            ],
            "description": "test-peer-2",
            "dns": [],
            "endpoint": None,
            "interface": "wg0",
            "keepalive": None,
            "mtu": None,
            "peers": [
                {
                    "address": [
                        "fde2:3a65:ca93:3125::4523:3425"
                    ],
                    "description": "test-server-2",
                    "public_key": "hBo5FSeVkb6WvGzpkitOIJYabLc835XbVjt6a7F0eHQ="
                }
            ],
            "post_down": [],
            "post_up": [],
            "pre_down": [],
            "pre_up": [],
            "preshared_key": None,
            "private_key": "kKzSxizUuGR28+DIL+w+WDT9OaTeDna6acb2axH19l8=",
            "public_key": "ShmphOZy2kccMQdPOw+s0PbM3O5QkNIcxXMa60KA31s=",
            "table": None
        }
    calculated_server_w_peer = {
            "address": [
                "fde2:3a65:ca93:3125::4523:3425"
            ],
            "allowed_ips": [
                "fde2:3a65:ca93:3125::/64",
                "fde2:3a65:ca93:3125::4523:3425/128"
            ],
            "description": "test-server-2",
            "dns": [],
            "endpoint": None,
            "interface": "wg0",
            "keepalive": None,
            "mtu": None,
            "peers": [
                {
                    "address": [
                        "fde2:3a65:ca93:3125::3425:4523"
                    ],
                    "description": "test-peer-2",
                    "public_key": "ShmphOZy2kccMQdPOw+s0PbM3O5QkNIcxXMa60KA31s="
                }
            ],
            "post_down": [],
            "post_up": [],
            "pre_down": [],
            "pre_up": [],
            "preshared_key": None,
            "private_key": "3cH3g4JwUdzg+q2Nqwvr9/WVJujWUa9NHy2PiY1jli4=",
            "public_key": "hBo5FSeVkb6WvGzpkitOIJYabLc835XbVjt6a7F0eHQ=",
            "subnet": [
                "fde2:3a65:ca93:3125::/64"
            ],
            "table": None
        }

    server = Server(
        'test-server-2',
        'fde2:3a65:ca93:3125::4523:3425/64',
        private_key='3cH3g4JwUdzg+q2Nqwvr9/WVJujWUa9NHy2PiY1jli4=',
    )

    assert server.json(sort_keys=True) == json.dumps(calculated_server, sort_keys=True)

    peer = server.peer(
        'test-peer-2',
        address='fde2:3a65:ca93:3125::3425:4523',
        private_key='kKzSxizUuGR28+DIL+w+WDT9OaTeDna6acb2axH19l8=',
    )

    assert peer.json(sort_keys=True) == json.dumps(calculated_peer, sort_keys=True)
    assert server.json(sort_keys=True) == json.dumps(calculated_server_w_peer, sort_keys=True)

    assert peer.json(sort_keys=True) == Peer(**calculated_peer).json(sort_keys=True)
    assert server.json(sort_keys=True) == Server(**calculated_server_w_peer).json(sort_keys=True)


def test_server_json_dump_dual_ips():

    # We're obliged to use `sort_keys=True` here, so that the output will match the
    # pre-built string exactly

    calculated_server = {
            "address": [
                "192.168.0.5",
                "fde2:3a65:ca93:3125::4523:3425"
            ],
            "allowed_ips": [
                "fde2:3a65:ca93:3125::4523:3425/128",
                "192.168.0.0/24",
                "192.168.0.5/32",
                "fde2:3a65:ca93:3125::/64"
            ],
            "description": "test-server-3",
            "dns": [],
            "endpoint": None,
            "interface": "wg0",
            "keepalive": None,
            "mtu": None,
            "peers": [],
            "post_down": [],
            "post_up": [],
            "pre_down": [],
            "pre_up": [],
            "preshared_key": None,
            "private_key": "ShmphOZy2kccMQdPOw+s0PbM3O5QkNIcxXMa60KA31s=",
            "public_key": "yw/9moFVd/UnkUZKWMwKbmx4uGFkt33HUxcL5fC5Nl0=",
            "subnet": [
                "192.168.0.0/24",
                "fde2:3a65:ca93:3125::/64"
            ],
            "table": None
        }
    calculated_peer = {
            "address": [
                "192.168.0.52",
                "fde2:3a65:ca93:3125::3425:4523"
            ],
            "allowed_ips": [
                "192.168.0.52/32",
                "fde2:3a65:ca93:3125::3425:4523/128"
            ],
            "description": "test-peer-3",
            "dns": [],
            "endpoint": None,
            "interface": "wg0",
            "keepalive": None,
            "mtu": None,
            "peers": [
                {
                    "address": [
                        "192.168.0.5",
                        "fde2:3a65:ca93:3125::4523:3425"
                    ],
                    "description": "test-server-3",
                    "public_key": "yw/9moFVd/UnkUZKWMwKbmx4uGFkt33HUxcL5fC5Nl0="
                }
            ],
            "post_down": [],
            "post_up": [],
            "pre_down": [],
            "pre_up": [],
            "preshared_key": None,
            "private_key": "0LUF7V6tpmH93dNDRRiBchAAFzfkiyFUNvpOyNwQdWc=",
            "public_key": "1loZYE8cKaENRmjUJI8f2suVq/MpPXfRIgRfJakdyUA=",
            "table": None
        }
    calculated_server_w_peer = {
            "address": [
                "192.168.0.5",
                "fde2:3a65:ca93:3125::4523:3425"
            ],
            "allowed_ips": [
                "fde2:3a65:ca93:3125::4523:3425/128",
                "192.168.0.0/24",
                "192.168.0.5/32",
                "fde2:3a65:ca93:3125::/64"
            ],
            "description": "test-server-3",
            "dns": [],
            "endpoint": None,
            "interface": "wg0",
            "keepalive": None,
            "mtu": None,
            "peers": [
                {
                    "address": [
                        "192.168.0.52",
                        "fde2:3a65:ca93:3125::3425:4523"
                    ],
                    "description": "test-peer-3",
                    "public_key": "1loZYE8cKaENRmjUJI8f2suVq/MpPXfRIgRfJakdyUA="
                }
            ],
            "post_down": [],
            "post_up": [],
            "pre_down": [],
            "pre_up": [],
            "preshared_key": None,
            "private_key": "ShmphOZy2kccMQdPOw+s0PbM3O5QkNIcxXMa60KA31s=",
            "public_key": "yw/9moFVd/UnkUZKWMwKbmx4uGFkt33HUxcL5fC5Nl0=",
            "subnet": [
                "192.168.0.0/24",
                "fde2:3a65:ca93:3125::/64"
            ],
            "table": None
        }

    server = Server(
        'test-server-3',
        ['192.168.0.0/24', 'fde2:3a65:ca93:3125::/64',],
        address=['192.168.0.5', 'fde2:3a65:ca93:3125::4523:3425',],
        private_key='ShmphOZy2kccMQdPOw+s0PbM3O5QkNIcxXMa60KA31s=',
    )

    assert server.json(sort_keys=True) == json.dumps(calculated_server, sort_keys=True)

    peer = server.peer(
        'test-peer-3',
        address=['192.168.0.52', 'fde2:3a65:ca93:3125::3425:4523',],
        private_key='0LUF7V6tpmH93dNDRRiBchAAFzfkiyFUNvpOyNwQdWc=',
    )

    assert peer.json(sort_keys=True) == json.dumps(calculated_peer, sort_keys=True)
    assert server.json(sort_keys=True) == json.dumps(calculated_server_w_peer, sort_keys=True)

    assert peer.json(sort_keys=True) == Peer(**calculated_peer).json(sort_keys=True)
    assert server.json(sort_keys=True) == Server(**calculated_server_w_peer).json(sort_keys=True)


def test_server_json_dump_with_nat_traversal():

    calculated_server = {
            "address": [
                "fde2:3a65:ca93:3125::4523:3425"
            ],
            "allowed_ips": [
                "fde2:3a65:ca93:3125::/64",
                "fde2:3a65:ca93:3125::4523:3425/128"
            ],
            "description": "test-server-2",
            "dns": [],
            "endpoint": None,
            "interface": "wg0",
            "keepalive": None,
            "mtu": None,
            "peers": [],
            "post_down": [
                'iptables -D FORWARD -i %i -o eth1 -j ACCEPT',
                'iptables -D FORWARD -i eth1 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
                'iptables -t nat -D POSTROUTING -o eth1 -j MASQUERADE',
            ],
            "post_up": [
                'iptables -A FORWARD -i %i -o eth1 -j ACCEPT',
                'iptables -A FORWARD -i eth1 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
                'iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE',
            ],
            "pre_down": [],
            "pre_up": [],
            "preshared_key": None,
            "private_key": "3cH3g4JwUdzg+q2Nqwvr9/WVJujWUa9NHy2PiY1jli4=",
            "public_key": "hBo5FSeVkb6WvGzpkitOIJYabLc835XbVjt6a7F0eHQ=",
            "subnet": [
                "fde2:3a65:ca93:3125::/64"
            ],
            "table": None
        }
    calculated_peer = {
            "address": [
                "fde2:3a65:ca93:3125::3425:4523"
            ],
            "allowed_ips": [
                "fde2:3a65:ca93:3125::3425:4523/128"
            ],
            "description": "test-peer-2",
            "dns": [],
            "endpoint": None,
            "interface": "wg0",
            "keepalive": None,
            "mtu": None,
            "peers": [
                {
                    "address": [
                        "fde2:3a65:ca93:3125::4523:3425"
                    ],
                    "description": "test-server-2",
                    "public_key": "hBo5FSeVkb6WvGzpkitOIJYabLc835XbVjt6a7F0eHQ="
                }
            ],
            "post_down": [
                'iptables -D FORWARD -i %i -o eth2 -j ACCEPT',
                'iptables -D FORWARD -i eth2 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
                'iptables -t nat -D POSTROUTING -o eth2 -j MASQUERADE',
            ],
            "post_up": [
                'iptables -A FORWARD -i %i -o eth2 -j ACCEPT',
                'iptables -A FORWARD -i eth2 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
                'iptables -t nat -A POSTROUTING -o eth2 -j MASQUERADE',
            ],
            "pre_down": [],
            "pre_up": [],
            "preshared_key": None,
            "private_key": "kKzSxizUuGR28+DIL+w+WDT9OaTeDna6acb2axH19l8=",
            "public_key": "ShmphOZy2kccMQdPOw+s0PbM3O5QkNIcxXMa60KA31s=",
            "table": None
        }
    calculated_server_w_peer = {
            "address": [
                "fde2:3a65:ca93:3125::4523:3425"
            ],
            "allowed_ips": [
                "fde2:3a65:ca93:3125::/64",
                "fde2:3a65:ca93:3125::4523:3425/128"
            ],
            "description": "test-server-2",
            "dns": [],
            "endpoint": None,
            "interface": "wg0",
            "keepalive": None,
            "mtu": None,
            "peers": [
                {
                    "address": [
                        "fde2:3a65:ca93:3125::3425:4523"
                    ],
                    "description": "test-peer-2",
                    "public_key": "ShmphOZy2kccMQdPOw+s0PbM3O5QkNIcxXMa60KA31s="
                }
            ],
            "post_down": [
                'iptables -D FORWARD -i %i -o eth1 -j ACCEPT',
                'iptables -D FORWARD -i eth1 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
                'iptables -t nat -D POSTROUTING -o eth1 -j MASQUERADE',
            ],
            "post_up": [
                'iptables -A FORWARD -i %i -o eth1 -j ACCEPT',
                'iptables -A FORWARD -i eth1 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
                'iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE',
            ],
            "pre_down": [],
            "pre_up": [],
            "preshared_key": None,
            "private_key": "3cH3g4JwUdzg+q2Nqwvr9/WVJujWUa9NHy2PiY1jli4=",
            "public_key": "hBo5FSeVkb6WvGzpkitOIJYabLc835XbVjt6a7F0eHQ=",
            "subnet": [
                "fde2:3a65:ca93:3125::/64"
            ],
            "table": None
        }

    server = Server(
        'test-server-2',
        'fde2:3a65:ca93:3125::4523:3425/64',
        private_key='3cH3g4JwUdzg+q2Nqwvr9/WVJujWUa9NHy2PiY1jli4=',
    )
    server.add_nat_traversal('eth1')

    assert server.json(sort_keys=True) == json.dumps(calculated_server, sort_keys=True)

    peer = server.peer(
        'test-peer-2',
        address='fde2:3a65:ca93:3125::3425:4523',
        private_key='kKzSxizUuGR28+DIL+w+WDT9OaTeDna6acb2axH19l8=',
    )
    peer.add_nat_traversal('eth2')

    assert peer.json(sort_keys=True) == json.dumps(calculated_peer, sort_keys=True)
    assert server.json(sort_keys=True) == json.dumps(calculated_server_w_peer, sort_keys=True)

    assert peer.json(sort_keys=True) == Peer(**calculated_peer).json(sort_keys=True)
    assert peer.json(sort_keys=True) == Peer(**json.loads(Peer(**calculated_peer).json(sort_keys=True))).json(sort_keys=True)
    assert server.json(sort_keys=True) == Server(**calculated_server_w_peer).json(sort_keys=True)
    assert server.json(sort_keys=True) == Server(**json.loads(Server(**calculated_server_w_peer).json(sort_keys=True))).json(sort_keys=True)
