
import pytest

from wireguard import (
    Config,
    Peer,
)


def test_description():
    address = '192.168.0.2'

    peer = Peer(
        'test-peer',
        address=address,
    )

    config = Config(peer)
    wg_config = config.local_config

    assert config.description == '# test-peer'

    # Check that these don't appear anywhere at all because of how basic this config is
    for option in ['DNS', 'PreUp', 'PostUp', 'PreDown', 'PostDown', 'SaveConfig', 'MTU', 'Table', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey', 'PublicKey']:
        assert f'{option} =' not in wg_config

    peer.description = None
    assert config.description is None


# Don't like the `dummy` value here, but pytest gets confused about the test arguments otherwise
@pytest.mark.parametrize(
    ('dns', 'dummy',),
    [
        (['2.2.2.2', '3.3.3.3', '1.1.1.1',], None,),
        (('3.3.3.3', '1.1.1.1', '2.2.2.2',), None,),
        ({'1.1.1.1', '2.2.2.2', '3.3.3.3',}, None,),
    ])
def test_multiple_dns(dns, dummy):
    address = '192.168.0.2'

    peer = Peer(
        'test-peer',
        address=address,
        dns=dns,
    )

    config = Config(peer)
    wg_config = config.local_config
    config_lines = wg_config.split('\n')

    # Because the set of DNS entries could return in any order, check that at least one is present
    assert (
        'DNS = 1.1.1.1,2.2.2.2,3.3.3.3' in config_lines or
        'DNS = 1.1.1.1,3.3.3.3,2.2.2.2' in config_lines or
        'DNS = 2.2.2.2,1.1.1.1,3.3.3.3' in config_lines or
        'DNS = 2.2.2.2,3.3.3.3,1.1.1.1' in config_lines or
        'DNS = 3.3.3.3,1.1.1.1,2.2.2.2' in config_lines or
        'DNS = 3.3.3.3,2.2.2.2,1.1.1.1' in config_lines
    )

    # Check that these don't appear anywhere at all because of how basic this config is
    for option in ['PreUp', 'PostUp', 'PreDown', 'PostDown', 'SaveConfig', 'MTU', 'Table', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey', 'PublicKey']:
        assert f'{option} =' not in wg_config

    peer.dns = None
    assert config.dns is None


def test_dns():
    address = '192.168.0.2'

    peer = Peer(
        'test-peer',
        address=address,
        dns='8.8.8.8',
    )

    config = Config(peer)
    wg_config = config.local_config
    config_lines = wg_config.split('\n')

    assert 'DNS = 8.8.8.8' in config_lines

    # Check that these don't appear anywhere at all because of how basic this config is
    for option in ['PreUp', 'PostUp', 'PreDown', 'PostDown', 'SaveConfig', 'MTU', 'Table', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey', 'PublicKey']:
        assert f'{option} =' not in wg_config

    peer.dns = None
    assert config.dns is None


def test_pre_up():
    address = '192.168.0.2'
    command = 'some-iptables-command'

    peer = Peer(
        'test-peer',
        address=address,
        pre_up=command,
    )

    config = Config(peer)
    wg_config = config.local_config
    config_lines = wg_config.split('\n')

    assert f'PreUp = {command}' in config_lines

    # Check that these don't appear anywhere at all because of how basic this config is
    for option in ['DNS', 'PostUp', 'PreDown', 'PostDown', 'SaveConfig', 'MTU', 'Table', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey', 'PublicKey']:
        assert f'{option} =' not in wg_config

    peer.pre_up = None
    assert config.pre_up is None


def test_pre_down():
    address = '192.168.0.2'
    command = 'some-iptables-command'

    peer = Peer(
        'test-peer',
        address=address,
        pre_down=command,
    )

    config = Config(peer)
    wg_config = config.local_config
    config_lines = wg_config.split('\n')

    assert f'PreDown = {command}' in config_lines

    # Check that these don't appear anywhere at all because of how basic this config is
    for option in ['DNS', 'PreUp', 'PostUp', 'PostDown', 'SaveConfig', 'MTU', 'Table', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey', 'PublicKey']:
        assert f'{option} =' not in wg_config

    peer.pre_down = None
    assert config.pre_down is None


def test_post_up():
    address = '192.168.0.2'
    command = 'some-iptables-command'

    peer = Peer(
        'test-peer',
        address=address,
        post_up=command,
    )

    config = Config(peer)
    wg_config = config.local_config
    config_lines = wg_config.split('\n')

    assert f'PostUp = {command}' in config_lines

    # Check that these don't appear anywhere at all because of how basic this config is
    for option in ['DNS', 'PreUp', 'PreDown', 'PostDown', 'SaveConfig', 'MTU', 'Table', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey', 'PublicKey']:
        assert f'{option} =' not in wg_config

    peer.post_up = None
    assert config.post_up is None


def test_post_down():
    address = '192.168.0.2'
    command = 'some-iptables-command'

    peer = Peer(
        'test-peer',
        address=address,
        post_down=command,
    )

    config = Config(peer)
    wg_config = config.local_config
    config_lines = wg_config.split('\n')

    assert f'PostDown = {command}' in config_lines

    # Check that these don't appear anywhere at all because of how basic this config is
    for option in ['DNS', 'PreUp', 'PostUp', 'PreDown', 'SaveConfig', 'MTU', 'Table', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey', 'PublicKey']:
        assert f'{option} =' not in wg_config

    peer.post_down = None
    assert config.post_down is None


@pytest.mark.parametrize(
    ('save_config', 'expected_output',),
    [
        (True, 'SaveConfig = true',),
        (False, 'SaveConfig = false',),
    ])
def test_save_config(save_config, expected_output):
    address = '192.168.0.2'

    peer = Peer(
        'test-peer',
        address=address,
        save_config=save_config,
    )

    config = Config(peer)
    wg_config = config.local_config
    config_lines = wg_config.split('\n')

    assert expected_output in config_lines

    # Check that these don't appear anywhere at all because of how basic this config is
    for option in ['DNS', 'PreUp', 'PostUp', 'PreDown', 'PostDown', 'MTU', 'Table', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey', 'PublicKey']:
        assert f'{option} =' not in wg_config

    peer.save_config = None
    assert config.save_config is None


def test_mtu():
    address = '192.168.0.2'

    peer = Peer(
        'test-peer',
        address=address,
        mtu=1280,
    )

    config = Config(peer)
    wg_config = config.local_config
    config_lines = wg_config.split('\n')

    assert 'MTU = 1280' in config_lines

    # Check that these don't appear anywhere at all because of how basic this config is
    for option in ['DNS', 'PreUp', 'PostUp', 'PreDown', 'PostDown', 'SaveConfig', 'Table', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey', 'PublicKey']:
        assert f'{option} =' not in wg_config

    peer.mtu = None
    assert config.mtu is None


def test_table():
    address = '192.168.0.2'

    peer = Peer(
        'test-peer',
        address=address,
        table='off',
    )

    config = Config(peer)
    wg_config = config.local_config
    config_lines = wg_config.split('\n')

    assert 'Table = off' in config_lines

    # Check that these don't appear anywhere at all because of how basic this config is
    for option in ['DNS', 'PreUp', 'PostUp', 'PreDown', 'PostDown', 'SaveConfig', 'MTU', 'AllowedIPs', 'Endpoint', 'PersistentKeepalive', 'PresharedKey', 'PublicKey']:
        assert f'{option} =' not in wg_config

    peer.table = None
    assert config.table is None


def test_comments():
    address = '192.168.0.2'

    comments = [
        'This is the first comment',
        'and this is another',
    ]

    peer = Peer(
        'test-peer',
        address=address,
        comments=comments,
    )

    config = peer.config

    for comment in comments:
        assert f'# {comment}' in config.local_config

    peer.add_comment('maybe we need a third')
    assert '# maybe we need a third' in config.local_config
