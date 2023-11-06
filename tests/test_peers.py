
import pytest

from subnet import (
    ip_address,
    IPv4Address,
    IPv6Address,
)

from wireguard import (
    INTERFACE,
    PORT,
    Config,
    Peer,
)
from wireguard.utils import public_key


@pytest.mark.parametrize(
    ('ipv4_address', 'ipv6_address',),
    [
        ('192.168.0.2', None,),
        (None, 'fde2:3a65:ca93:3125:1234:abcd:4321:32',),
        ('192.168.0.2', 'fde2:3a65:ca93:3125:1234:abcd:4321:32',),
    ])
def test_basic_peer(ipv4_address, ipv6_address):

    if ipv4_address and ipv6_address:
        address = [ipv4_address, ipv6_address]
    elif ipv6_address:
        address = ipv6_address
    else:
        address = ipv4_address

    peer = Peer(
        'test-peer',
        address=address,
    )

    if ipv4_address:
        assert isinstance(peer.ipv4, IPv4Address)
        assert str(peer.ipv4) == ipv4_address
    else:
        assert peer.ipv4 is None

    if ipv6_address:
        assert isinstance(peer.ipv6, IPv6Address)
        assert str(peer.ipv6) == ipv6_address
    else:
        assert peer.ipv6 is None

    assert peer.port == PORT
    assert peer.interface == INTERFACE

    assert peer.private_key is not None
    assert peer.public_key is not None
    assert peer.public_key == public_key(peer.private_key)

    assert not peer.peers
    assert not peer.dns
    assert not peer.mtu
    assert not peer.table
    assert not peer.pre_up
    assert not peer.post_up
    assert not peer.pre_down
    assert not peer.post_down
    assert not peer.keepalive
    assert not peer.preshared_key

    config = peer.config
    assert isinstance(config, Config)

    wg_config = config.local_config
    config_lines = wg_config.split('\n')
    # Ensure that [Interface] is first in the config, allowing for blank lines before
    for line in config_lines:
        if line:
            assert line == '[Interface]'
            break

    if ipv4_address and ipv6_address:
        assert (
            f'Address = {ipv4_address}/32,{ipv6_address}/128' in config_lines or
            f'Address = {ipv6_address}/128,{ipv4_address}/32' in config_lines
        )
    elif ipv6_address:
        assert f'Address = {ipv6_address}/128' in config_lines
    else:
        assert f'Address = {ipv4_address}/32' in config_lines

    assert '# test-peer' not in config_lines  # Should only be present in Peer section on remote
    assert '[Peer]' not in config_lines  # We haven't configured any peers, so this shouldn't exist

    # None of these have been set for this peer. They should not be in the config file
    assert 'DNS =' not in wg_config
    assert 'MTU =' not in wg_config
    assert 'Table =' not in wg_config
    assert 'PreUp =' not in wg_config
    assert 'PostUp =' not in wg_config
    assert 'PreDown =' not in wg_config
    assert 'PostDown =' not in wg_config
    assert 'PresharedKey =' not in wg_config
    assert 'PersistentKeepalive =' not in wg_config


@pytest.mark.parametrize('mtu', [1280, 1420,])
def test_peer_mtu(mtu):
    address = '192.168.0.2'

    peer = Peer(
        'test-peer',
        address=address,
        mtu=mtu,
    )

    assert isinstance(peer.ipv4, IPv4Address)
    assert str(peer.ipv4) == address
    assert peer.ipv6 is None

    assert peer.port == PORT
    assert peer.interface == INTERFACE

    assert peer.private_key is not None
    assert peer.public_key is not None
    assert peer.public_key == public_key(peer.private_key)

    assert peer.mtu == mtu

    # Ensure nothing else got set
    assert not peer.peers
    assert not peer.dns
    assert not peer.table
    assert not peer.pre_up
    assert not peer.post_up
    assert not peer.pre_down
    assert not peer.post_down
    assert not peer.keepalive
    assert not peer.preshared_key

    config = peer.config
    config_lines = config.local_config.split('\n')
    assert f'MTU = {mtu}' in config_lines


@pytest.mark.parametrize(
    ('mtu', 'exception_message',),
    [
        ('1280', 'must be an integer',),  # Technically valid, but being sent as str
        (False, 'must be an integer',),
        (True, 'must be an integer',),
        ('beep', 'must be an integer',),
        (768, 'must be in the range',),
        (1279, 'must be in the range',),
        (1481, 'must be in the range',),
        (2001, 'must be in the range',),
    ])
def test_peer_invalid_mtu(mtu, exception_message):
    address = '192.168.0.2'

    with pytest.raises(ValueError) as exc:
        peer = Peer(
            'test-peer',
            address=address,
            mtu=mtu,
        )

    assert exception_message in str(exc.value)


def test_peer_dns():
    address = '192.168.0.2'
    dns = '1.1.1.1'

    peer = Peer(
        'test-peer',
        address=address,
        dns=ip_address(dns),
    )

    assert isinstance(peer.ipv4, IPv4Address)
    assert str(peer.ipv4) == address
    assert peer.ipv6 is None

    assert peer.port == PORT
    assert peer.interface == INTERFACE

    assert peer.private_key is not None
    assert peer.public_key is not None
    assert peer.public_key == public_key(peer.private_key)

    assert peer.dns is not None
    dns_found = False
    for entry in peer.dns:
        if str(entry) == dns:
            dns_found = True
            break

    assert dns_found

    # Ensure nothing else got set
    assert not peer.peers
    assert not peer.mtu
    assert not peer.table
    assert not peer.pre_up
    assert not peer.post_up
    assert not peer.pre_down
    assert not peer.post_down
    assert not peer.keepalive
    assert not peer.preshared_key

    config = peer.config
    config_lines = config.local_config.split('\n')
    assert f'DNS = {dns}' in config_lines


@pytest.mark.parametrize(
    ('dns', 'exception_message',),
    [
        ('1280', 'Could not convert to IP',),
        # Don't need to test `False`, it's prevented from being used without raising an error
        (True, 'Could not convert to IP',),
        ('beep', 'Could not convert to IP',),
        ('1.1.1', 'Could not convert to IP',),
        ('1.1.1.1.1', 'Could not convert to IP',),
        (-1, 'Could not convert to IP',),
        # ints > 0 are translated to their appropriate IPv4/v6 address without an error
    ])
def test_peer_invalid_dns(dns, exception_message):
    address = '192.168.0.2'

    with pytest.raises(ValueError) as exc:
        peer = Peer(
            'test-peer',
            address=address,
            dns=dns,
        )

    assert exception_message in str(exc.value)


def test_peer_comments():
    address = '192.168.0.2'
    dns = '1.1.1.1'
    comments = [
       'This is the first comment',
       'and this is another',
    ]

    peer = Peer(
        'test-peer',
        address=address,
        dns=ip_address(dns),
        comments=comments,
    )

    assert len(peer.comments) == 2
    for comment in comments:
        assert comment in peer.comments
