

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
