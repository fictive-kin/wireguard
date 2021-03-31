
import pytest
from unittest.mock import (
    call,
    mock_open,
    patch,
)

from subnet import ip_network, IPv4Network, IPv4Address

from wireguard import (
    Config,
    ServerConfig,
    Peer,
    Server,
)
from wireguard.utils import IPAddressSet


def test_basic_config():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
    )

    config = ServerConfig(server)
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

    config = Config(peer)
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


def test_inadmissible_non_peer():
    class NonPeer():
        attrib1 = IPAddressSet()
        attrib2 = 'something'

    with pytest.raises(ValueError) as exc:
        config = Config(NonPeer())
        assert 'provide a valid Peer' in str(exc.value)


def test_admissible_non_peer():
    class NonPeer():
        allowed_ips = IPAddressSet()
        public_key = 'something'

    config = Config(NonPeer())
    for line in config.local_config.split('\n'):
        if line:
            assert line == '[Interface]'

    assert '[Peer]' in config.remote_config
    assert 'PublicKey = something' in config.remote_config


def test_write_server_config():

    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
    )

    with patch('builtins.open', mock_open()) as mo:
        server.config().write()

        mo.assert_has_calls([
            call('/etc/wireguard/wg0.conf', 'w'),
            call('/etc/wireguard/wg0-peers.conf', 'w'),
        ], any_order=True)


def test_write_peer_config():

    address = '192.168.0.1'

    peer = Peer(
        'test-peer',
        address=address,
    )

    with patch('builtins.open', mock_open()) as mo:
        peer.config().write()

        mo.assert_has_calls([
            call('/etc/wireguard/wg0.conf', 'w'),
        ], any_order=True)
