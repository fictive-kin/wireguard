
import pytest
from unittest.mock import (
    call,
    mock_open,
    patch,
)

from wireguard import (
    Config,
    ServerConfig,
    Peer,
    Server,
)
from wireguard.utils import IPAddressSet


def test_basic_server():
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
    )

    config = ServerConfig(server)
    wg_config = config.local_config
    config_lines = wg_config.split('\n')

    # Ensure that [Interface] is first in the config, allowing for blank lines before
    for line in config_lines:
        if line:
            assert line == '[Interface]'
            break

    # Check that these are on a line alone in the config output
    assert f'Address = {address}/24' in config_lines
    assert '# test-server' not in config_lines  # Should only be present in Peer section on remote
    assert '[Peer]' not in config_lines  # We haven't configured any peers, so this shouldn't exist

    # Check that these don't appear anywhere at all because of how basic this config is
    for option in ['DNS', 'PreUp', 'PostUp', 'PreDown', 'PostDown', 'SaveConfig', 'MTU', 'Table', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey', 'PublicKey']:
        assert f'{option} =' not in wg_config


def test_basic_peer():
    address = '192.168.0.2'

    peer = Peer(
        'test-peer',
        address=address,
    )

    config = Config(peer)
    wg_config = config.local_config
    config_lines = wg_config.split('\n')

    # Ensure that [Interface] is first in the config, allowing for blank lines before
    for line in config_lines:
        if line:
            assert line == '[Interface]'
            break

    assert f'Address = {address}/32' in config_lines

    assert '# test-peer' not in config_lines  # Should only be present in Peer section on remote
    assert '[Peer]' not in config_lines  # We haven't configured any peers, so this shouldn't exist

    # Check that these don't appear anywhere at all because of how basic this config is
    for option in ['DNS', 'PreUp', 'PostUp', 'PreDown', 'PostDown', 'SaveConfig', 'MTU', 'Table', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey', 'PublicKey']:
        assert f'{option} =' not in wg_config


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


def test_write_server_config_no_params():

    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
    )

    with patch('builtins.open', mock_open()) as mo:
        server.config.write()

        mo.assert_has_calls([
            call('/etc/wireguard/wg0.conf', mode='w', encoding='utf-8'),
            call('/etc/wireguard/wg0-peers.conf', mode='w', encoding='utf-8'),
        ], any_order=True)


@pytest.mark.parametrize(
    ('interface', 'path', 'full_path', 'peers_full_path'),
    [
        (None, None, '/etc/wireguard/wg0.conf', '/etc/wireguard/wg0-peers.conf',),  # Default options
        ('wg3', None, '/etc/wireguard/wg3.conf', '/etc/wireguard/wg3-peers.conf',),
        (None, '/opt/my-wg-dir', '/opt/my-wg-dir/wg0.conf', '/opt/my-wg-dir/wg0-peers.conf',),
        ('wg1', '/opt/my-other-wg-dir', '/opt/my-other-wg-dir/wg1.conf', '/opt/my-other-wg-dir/wg1-peers.conf',),
    ])
def test_write_server_config(interface, path, full_path, peers_full_path):
    subnet = '192.168.0.0/24'
    address = '192.168.0.1'

    server = Server(
        'test-server',
        subnet,
        address=address,
        interface=interface
    )

    config = server.config
    assert config.full_path(path) == full_path
    assert config.peers_full_path(path) == peers_full_path

    with patch('builtins.open', mock_open()) as mo:
        config.write(path)

        mo.assert_has_calls([
            call(full_path, mode='w', encoding='utf-8'),
            call(peers_full_path, mode='w', encoding='utf-8'),
        ], any_order=True)


def test_write_peer_config_no_params():

    address = '192.168.0.1'

    peer = Peer(
        'test-peer',
        address=address,
    )

    with patch('builtins.open', mock_open()) as mo:
        peer.config.write()

        mo.assert_has_calls([
            call('/etc/wireguard/wg0.conf', mode='w', encoding='utf-8'),
        ], any_order=True)


@pytest.mark.parametrize(
    ('interface', 'path', 'full_path',),
    [
        (None, None, '/etc/wireguard/wg0.conf',),  # Default options
        ('wg3', None, '/etc/wireguard/wg3.conf',),
        (None, '/opt/my-wg-dir', '/opt/my-wg-dir/wg0.conf',),
        ('wg1', '/opt/my-other-wg-dir', '/opt/my-other-wg-dir/wg1.conf',),
    ])
def test_write_peer_config(interface, path, full_path):
    address = '192.168.0.2'

    peer = Peer(
        'test-peer',
        address=address,
        interface=interface,
    )

    config = Config(peer)

    assert config.full_path(path) == full_path

    with patch('builtins.open', mock_open()) as mo:
        peer.config.write(path)

        mo.assert_has_calls([
            call(full_path, mode='w', encoding='utf-8'),
        ], any_order=True)
