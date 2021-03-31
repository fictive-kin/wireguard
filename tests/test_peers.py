

from subnet import ip_network, IPv4Network, IPv4Address

from wireguard import (
    INTERFACE,
    PORT,
    Config,
    ServerConfig,
    Peer,
    Server,
)
from wireguard.utils import public_key


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


def test_basic_peer():
    address = '192.168.0.2'

    peer = Peer(
        'test-peer',
        address=address,
    )

    assert isinstance(peer.address, IPv4Address)
    assert str(peer.address) == address

    assert peer.port == PORT
    assert peer.interface == INTERFACE

    assert peer.private_key is not None
    assert peer.public_key is not None
    assert peer.public_key == public_key(peer.private_key)

    assert not peer.peers
    assert not peer.pre_up
    assert not peer.post_up
    assert not peer.pre_down
    assert not peer.post_down

    config = peer.config()
    assert isinstance(config, Config)

    config_lines = config.local_config.split('\n')
    # Ensure that [Interface] is first in the config, allowing for blank lines before
    for line in config_lines:
        if line:
            assert line == '[Interface]'
            break
    assert f'Address = {address}/32' in config_lines

    assert 'DNS =' not in config_lines
    assert '# test-peer' not in config_lines  # Should only be present in Peer section on remote
    assert '[Peer]' not in config_lines  # We haven't configured any peers, so this shouldn't exist


def test_both_server_and_peer():
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


def test_dns_server_and_peer():
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
