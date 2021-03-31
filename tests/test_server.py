
import pytest

from subnet import ip_network, IPv4Network, IPv4Address

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

    assert isinstance(server.address, IPv4Address)
    assert isinstance(server.subnet, IPv4Network)
    assert str(server.address) == address
    assert server.address in ip_network(subnet)

    assert server.port == PORT
    assert server.interface == INTERFACE

    assert server.private_key is not None
    assert server.public_key is not None
    assert server.public_key == public_key(server.private_key)

    assert not server.peers
    assert not server.pre_up
    assert not server.post_up
    assert not server.pre_down
    assert not server.post_down

    config = server.config()
    assert isinstance(config, ServerConfig)

    config_lines = config.local_config.split('\n')

    # Ensure that [Interface] is first in the config, allowing for blank lines before
    for line in config_lines:
        if line:
            assert line == '[Interface]'
            break

    assert f'Address = {address}/24' in config_lines

    assert 'DNS =' not in config_lines
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
    assert isinstance(peer.address, IPv4Address)
    assert peer.address in ip_network(subnet)
    assert peer.address != server.address

    assert server.private_key is not None
    assert peer.private_key is not None
    assert peer.public_key != server.public_key
    assert peer.private_key != server.private_key

    assert server not in server.peers
    assert server in peer.peers
    assert peer not in peer.peers
    assert peer in server.peers

    server_config = server.config()
    peer_config = peer.config()
    assert isinstance(server_config, ServerConfig)
    assert isinstance(peer_config, Config)

    server_lines = server_config.local_config.split('\n')
    peer_lines = peer_config.local_config.split('\n')

    assert f'Address = {server.address}/{server.subnet.prefixlen}' in server_lines
    assert f'Address = {peer.address}/{peer.address.max_prefixlen}' not in server_lines
    assert '[Peer]' in server_lines
    assert '# test-server' not in server_lines  # Should only be present in Peer section on remote
    assert '# test-peer' in server_lines

    assert f'Address = {peer.address}/{peer.address.max_prefixlen}' in peer_lines
    assert f'Address = {server.address}/{server.subnet.prefixlen}' not in peer_lines
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

    config = server.config().local_config
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

    server_config = server.config()
    peer_config = peer.config()
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
