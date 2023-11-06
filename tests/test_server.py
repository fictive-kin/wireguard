
import pytest

from subnet import (
    ip_network,
    IPv4Network,
    IPv4Address,
)

from wireguard import (
    INTERFACE,
    PORT,
    Config,
    ServerConfig,
    Peer,
    Server,
)
from wireguard.utils import generate_key, public_key


def test_basic_server():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
    )

    assert isinstance(server.ipv4, IPv4Address)
    assert isinstance(server.ipv4_subnet, IPv4Network)
    assert str(server.ipv4) == address
    assert server.ipv4 in ip_network(subnet)
    assert server.ipv6 is None
    assert server.ipv6_subnet is None

    assert server.port == PORT
    assert server.interface == INTERFACE

    assert server.private_key is not None
    assert server.public_key is not None
    assert server.public_key == public_key(server.private_key)

    assert not server.peers
    assert not server.dns
    assert not server.mtu
    assert not server.table
    assert not server.pre_up
    assert not server.post_up
    assert not server.pre_down
    assert not server.post_down
    assert not server.preshared_key
    assert not server.keepalive

    config = server.config
    assert isinstance(config, ServerConfig)

    config_lines = config.local_config.split('\n')

    # Ensure that [Interface] is first in the config, allowing for blank lines before
    for line in config_lines:
        if line:
            assert line == '[Interface]'
            break

    assert f'Address = {address}/24' in config_lines

    assert '# test-server' not in config_lines  # Should only be present in Peer section on remote
    assert '[Peer]' not in config_lines  # We haven't configured any peers, so this shouldn't exist


def test_server_with_a_peer():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
    )

    peer = server.peer(
        'test-peer',
    )

    assert isinstance(peer, Peer)
    assert isinstance(peer.ipv4, IPv4Address)
    assert peer.ipv4 in ip_network(subnet)
    assert peer.ipv4 != server.ipv4
    assert peer.ipv6 is None

    assert server.private_key is not None
    assert peer.private_key is not None
    assert peer.public_key != server.public_key
    assert peer.private_key != server.private_key

    assert server not in server.peers
    assert server in peer.peers
    assert peer not in peer.peers
    assert peer in server.peers

    server_config = server.config
    peer_config = peer.config
    assert isinstance(server_config, ServerConfig)
    assert isinstance(peer_config, Config)

    server_lines = server_config.local_config.split('\n')
    peer_lines = peer_config.local_config.split('\n')

    assert f'Address = {server.ipv4}/{server.ipv4_subnet.prefixlen}' in server_lines
    assert f'Address = {peer.ipv4}/{peer.ipv4.max_prefixlen}' not in server_lines
    assert '[Peer]' in server_lines
    assert '# test-server' not in server_lines  # Should only be present in Peer section on remote
    assert '# test-peer' in server_lines

    assert f'Address = {peer.ipv4}/{peer.ipv4.max_prefixlen}' in peer_lines
    assert f'Address = {server.ipv4}/{server.ipv4_subnet.prefixlen}' not in peer_lines
    assert '[Peer]' in peer_lines
    assert '# test-peer' not in peer_lines  # Should only be present in Peer section on remote
    assert '# test-server' in peer_lines


def test_server_nat_traversal():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
    )

    server.add_nat_traversal('eth1')

    assert len(server.post_up) == 3
    for line in server.post_up:
        assert 'eth1' in line

    assert len(server.post_down) == 3
    for line in server.post_down:
        assert 'eth1' in line

    config = server.config.local_config
    assert 'PostUp' in config
    assert 'PostDown' in config
    assert 'iptables' in config
    assert 'eth1' in config


def test_dns_in_server_and_peer():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'
    dns = '8.8.8.8'

    server = Server(
        'test-server',
        subnet,
        address=address,
        dns=dns,
    )

    peer = server.peer(
        'test-peer',
    )

    server_config = server.config
    peer_config = peer.config
    assert isinstance(server_config, ServerConfig)
    assert isinstance(peer_config, Config)

    server_lines = server_config.local_config.split('\n')
    peer_lines = peer_config.local_config.split('\n')

    assert f'DNS = {dns}' in server_lines
    assert f'DNS = {dns}' in peer_lines


def test_server_with_multiple_peers():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
    )

    peer1 = server.peer(
        'test-peer1',
    )

    peer2 = server.peer(
        'test-peer2',
    )

    peer3 = server.peer(
        'test-peer3',
    )

    assert len(server.peers) == 3
    assert server not in server.peers

    peers = []
    for peer in server.peers:
        assert peer.private_key is not None
        assert peer.private_key != server.private_key
        peers.append(peer)

    assert peers[0].private_key != peers[1].private_key
    assert peers[0].private_key != peers[2].private_key
    assert peers[1].private_key != peers[2].private_key


def test_server_with_peer_duplicate_address():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
    )

    with pytest.raises(ValueError) as exc:
        peer1 = server.peer(
            'test-peer1',
            address=address,
        )
        assert 'is not unique' in str(exc.value)

    assert len(server.peers) == 0


def test_server_with_peer_duplicate_key():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'
    private_key = generate_key()

    server = Server(
        'test-server',
        subnet,
        address=address,
        private_key=private_key,
    )

    with pytest.raises(ValueError) as exc:
        peer1 = server.peer(
            'test-peer1',
            private_key=private_key,
        )
        assert 'is not unique' in str(exc.value)

    assert len(server.peers) == 0


@pytest.mark.parametrize('psk', ['my-preshared-key', '1234567890', 987654321,])
def test_server_preshared_key(psk):
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
        preshared_key=psk,
    )

    peer = server.peer(
        'test-peer',
    )

    assert server.public_key != peer.public_key

    assert server.preshared_key == psk
    assert peer.preshared_key == psk

    server_config = server.config
    peer_config = peer.config
    assert isinstance(server_config, ServerConfig)
    assert isinstance(peer_config, Config)

    server_lines = server_config.local_config.split('\n')
    peer_lines = peer_config.local_config.split('\n')

    assert f'PresharedKey = {psk}' in server_lines
    assert f'PresharedKey = {psk}' in peer_lines


def test_server_preshared_key_single_peer():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'
    psk = 'my-preshared-key'

    server = Server(
        'test-server',
        subnet,
        address=address,
    )

    peer = server.peer(
        'psk-peer',
        preshared_key=psk,
    )

    no_psk_peer = server.peer(
        'non-psk-peer',
    )

    assert server.public_key != peer.public_key

    assert server.preshared_key is None
    assert peer.preshared_key == psk
    assert no_psk_peer.preshared_key is None

    server_config = server.config
    peer_config = peer.config
    no_psk_peer_config = no_psk_peer.config
    assert isinstance(server_config, ServerConfig)
    assert isinstance(peer_config, Config)
    assert isinstance(no_psk_peer_config, Config)

    server_lines = server_config.local_config.split('\n')
    peer_lines = peer_config.local_config.split('\n')

    assert f'PresharedKey = {psk}' in server_lines
    assert f'PresharedKey = {psk}' in peer_lines

    # Shouldn't be in the no_psk_peer, since it was empty at the server level
    assert f'PresharedKey = {psk}' not in no_psk_peer_config.local_config


def test_server_mismatched_preshared_key():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'
    server_psk = 'server-key'
    peer_psk = 'peer-key'

    server = Server(
        'test-server',
        subnet,
        address=address,
        preshared_key=server_psk,
    )

    peer = server.peer(
        'test-peer',
        preshared_key=peer_psk,
    )

    with pytest.raises(ValueError) as exc:
        server_config = server.config.local_config

    assert 'keys do not match' in str(exc.value)

    with pytest.raises(ValueError) as exc:
        peer_config = peer.config.local_config

    assert 'keys do not match' in str(exc.value)


@pytest.mark.parametrize('keepalive', [45, 21, 5, 92,])
def test_server_keepalive(keepalive):
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
        keepalive=keepalive,
    )

    peer = server.peer(
        'test-peer',
    )

    assert server.public_key != peer.public_key

    assert server.keepalive == keepalive
    assert peer.keepalive == keepalive

    server_config = server.config
    peer_config = peer.config
    assert isinstance(server_config, ServerConfig)
    assert isinstance(peer_config, Config)

    server_lines = server_config.local_config.split('\n')
    peer_lines = peer_config.local_config.split('\n')

    assert f'PersistentKeepalive = {keepalive}' in peer_lines
    assert f'PersistentKeepalive = {keepalive}' in server_lines


def test_server_keepalive_single_peer():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'
    keepalive = 45

    server = Server(
        'test-server',
        subnet,
        address=address,
    )

    peer = server.peer(
        'test-peer',
        keepalive=keepalive,
    )

    assert server.public_key != peer.public_key

    assert server.keepalive is None
    assert peer.keepalive == keepalive

    server_config = server.config
    peer_config = peer.config
    assert isinstance(server_config, ServerConfig)
    assert isinstance(peer_config, Config)

    server_lines = server_config.local_config.split('\n')
    peer_lines = peer_config.local_config.split('\n')

    assert f'PersistentKeepalive = {keepalive}' in peer_lines
    assert f'PersistentKeepalive = {keepalive}' not in server_lines


def test_server_mismatched_keepalive():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'
    server_keepalive = 45
    peer_keepalive = 25

    server = Server(
        'test-server',
        subnet,
        address=address,
        keepalive=server_keepalive,
    )

    peer = server.peer(
        'test-peer',
        keepalive=peer_keepalive,
    )

    assert server.public_key != peer.public_key

    assert server.keepalive == server_keepalive
    assert peer.keepalive == peer_keepalive

    server_config = server.config
    peer_config = peer.config
    assert isinstance(server_config, ServerConfig)
    assert isinstance(peer_config, Config)

    server_lines = server_config.local_config.split('\n')
    peer_lines = peer_config.local_config.split('\n')

    assert f'PersistentKeepalive = {peer_keepalive}' in peer_lines
    assert f'PersistentKeepalive = {server_keepalive}' in server_lines


def test_server_mtu():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'
    mtu = 1280

    server = Server(
        'test-server',
        subnet,
        address=address,
        mtu=mtu,
    )

    peer = server.peer(
        'test-peer',
    )

    assert server.public_key != peer.public_key

    assert server.mtu == mtu
    assert peer.mtu == mtu

    server_config = server.config
    peer_config = peer.config
    assert isinstance(server_config, ServerConfig)
    assert isinstance(peer_config, Config)

    server_lines = server_config.local_config.split('\n')
    peer_lines = peer_config.local_config.split('\n')

    assert f'MTU = {mtu}' in peer_lines
    assert f'MTU = {mtu}' in server_lines


@pytest.mark.parametrize(
    ('server_mtu', 'peer_mtu',),
    [
        (1280, 1420,),
        (None, 1420,),
    ])
def test_server_mismatched_mtu(server_mtu, peer_mtu):
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
        mtu=server_mtu,
    )

    with pytest.raises(ValueError) as exc:
        peer = server.peer(
            'test-peer',
            mtu=peer_mtu,
        )

    assert 'MTU cannot be different' in str(exc.value)


@pytest.mark.parametrize('table', [432, 'auto', 'off'])
def test_server_table(table):
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
        table=table,
    )

    peer = server.peer(
        'test-peer',
    )

    assert server.public_key != peer.public_key

    assert server.table is not None
    assert server.table == table

    assert not peer.table

    server_config = server.config
    peer_config = peer.config
    assert isinstance(server_config, ServerConfig)
    assert isinstance(peer_config, Config)

    server_lines = server_config.local_config.split('\n')
    peer_lines = peer_config.local_config.split('\n')

    assert f'Table = {table}' not in peer_lines
    assert f'Table = {table}' in server_lines


@pytest.mark.parametrize(
    ('table', 'exception_message',),
    [
        (False, 'must be "auto", "off" or an integer value',),
        (True, 'must be "auto", "off" or an integer value',),
        ('253', 'must be "auto", "off" or an integer value',),
        ('beep', 'must be "auto", "off" or an integer value',),
        (254, 'must be in the ranges',),
        (0, 'must be in the ranges',),
        (2147483648, 'must be in the ranges',),
    ])
def test_server_invalid_table(table, exception_message):
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    with pytest.raises(ValueError) as exc:
        server = Server(
            'test-server',
            subnet,
            address=address,
            table=table,
        )

    assert exception_message in str(exc.value)


@pytest.mark.parametrize(
    (
        'ipv4_subnet_with_host_bits',
        'ipv4_subnet',
        'ipv4_address',
        'ipv6_subnet_with_host_bits',
        'ipv6_subnet',
        'ipv6_address',
    ),
    [
        ('192.168.0.5/24', '192.168.0.0/24', '192.168.0.5', None, None, None,),
        (
            None, None, None,
           'fde2:3a65:ca93:3125::4523:3425/64',
           'fde2:3a65:ca93:3125::/64',
           'fde2:3a65:ca93:3125::4523:3425',
        ),
        (
           '10.12.2.18/16',
           '10.12.0.0/16',
           '10.12.2.18',
           'fd1d:59db:21c2:9842:5678:deed:beef:973/64',
           'fd1d:59db:21c2:9842::/64',
           'fd1d:59db:21c2:9842:5678:deed:beef:973',
        ),
    ])
def test_server_subnet_with_host_bits(ipv4_subnet_with_host_bits, ipv4_subnet, ipv4_address,
                                      ipv6_subnet_with_host_bits, ipv6_subnet, ipv6_address):

    if ipv4_subnet_with_host_bits and ipv6_subnet_with_host_bits:
        subnet_with_host_bits = [ipv4_subnet_with_host_bits, ipv6_subnet_with_host_bits]
    elif ipv6_subnet_with_host_bits:
        subnet_with_host_bits = ipv6_subnet_with_host_bits
    else:
        subnet_with_host_bits = ipv4_subnet_with_host_bits

    server = Server(
        'test-server',
        subnet_with_host_bits,
    )

    assert server.ipv4_subnet != server.ipv6_subnet

    if ipv4_subnet_with_host_bits:
        assert str(server.ipv4_subnet) == ipv4_subnet
        assert str(server.ipv4) == ipv4_address
    else:
        assert server.ipv4_subnet is None
        assert server.ipv4 is None

    if ipv6_subnet_with_host_bits:
        assert str(server.ipv6_subnet) == ipv6_subnet
        assert str(server.ipv6) == ipv6_address
    else:
        assert server.ipv6_subnet is None
        assert server.ipv6 is None


@pytest.mark.parametrize(
    ('subnet', 'address', 'exception_message',),
    [
        (False, None, 'does not appear to be an IPv4 or IPv6 network',),
        (True, None, 'does not appear to be an IPv4 or IPv6 network',),
        (None, None, 'does not appear to be an IPv4 or IPv6 network',),
        ('beep', None, 'does not appear to be an IPv4 or IPv6 address',),
        (-1, None, 'does not appear to be an IPv4 or IPv6 network',),
        ('192.168.1.12/24', '192.168.1.1', 'both an address AND a subnet',),
        ('192.168.1.12/32', None, 'that only gives you 1 IP address',),
        ('fde2:3a65:ca93:3125::4523:3425/128', None, 'that only gives you 1 IP address',),
        (
           'fde2:3a65:ca93:3125::4523:3425/64',
           'fde2:3a65:ca93:3125::5234:a423',
           'both an address AND a subnet',
        ),
        (
            [
                'fde2:3a65:ca93:3125::4523:3425/64',
                '10.10.10.10/16',
                'fd1d:59db:21c2:9842:5678:deed:beef:973/64',
            ],
            None,
            'cannot set more than 2 core subnets',
        ),
        (
            ['10.10.10.10/16', '10.250.250.250/16',],
            None,
            'cannot set 2 IPv4 core subnets',
        ),
        (
            [
                'fde2:3a65:ca93:3125::4523:3425/64',
                'fd1d:59db:21c2:9842:5678:deed:beef:973/64',
            ],
            None,
            'cannot set 2 IPv6 core subnets',
        ),
    ])
def test_server_invalid_subnet(subnet, address, exception_message):

    with pytest.raises(ValueError) as exc:
        server = Server(
            'test-server',
            subnet,
            address=address,
        )

    assert exception_message in str(exc.value)
