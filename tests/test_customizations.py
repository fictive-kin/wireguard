
import pytest

from subnet import (
    ip_address,
    IPv4Address,
)

from wireguard import (
    Config,
    Interface,
    Peer,
)


class MyCustomInterface(Interface):
    pass


class MyCustomConfig(Config):
    pass


def test_peer_custom_config_cls():
    address = '192.168.0.2'
    dns = '1.1.1.1'

    peer = Peer(
        'test-peer',
        address=address,
        dns=ip_address(dns),
        config_cls=MyCustomConfig,
    )

    assert isinstance(peer.config, MyCustomConfig)


@pytest.mark.parametrize(
    ('cls',),
    [
        (MyCustomInterface,),
        (IPv4Address,),
    ],
)
def test_peer_invalid_custom_config_cls(cls):
    address = '192.168.0.2'
    dns = '1.1.1.1'

    with pytest.raises(ValueError):
        peer = Peer(
            'test-peer',
            address=address,
            dns=ip_address(dns),
            config_cls=cls,
        )


def test_peer_custom_service_cls():
    address = '192.168.0.2'
    dns = '1.1.1.1'

    peer = Peer(
        'test-peer',
        address=address,
        dns=ip_address(dns),
        service_cls=MyCustomInterface,
    )

    assert isinstance(peer.service, MyCustomInterface)


@pytest.mark.parametrize(
    ('cls',),
    [
        (MyCustomConfig,),
        (IPv4Address,),
    ],
)
def test_peer_invalid_custom_service_cls(cls):
    address = '192.168.0.2'
    dns = '1.1.1.1'

    with pytest.raises(ValueError):
        peer = Peer(
            'test-peer',
            address=address,
            dns=ip_address(dns),
            service_cls=cls,
        )
