
import pytest

from wireguard import (
    Peer,
)


def test_peer_qrcode():

    # If qrcode is present in the venv, test it works.
    pytest.importorskip('qrcode', reason='QRCode is NOT available')

    address = '192.168.0.1'

    peer = Peer(
        'test-peer',
        address=address,
    )

    assert peer.config.qrcode


def test_peer_qrcode_not_present():

    try:
        import qrcode
        pytest.skip('QRCode is available')
    except ImportError:
        pass

    address = '192.168.0.1'

    peer = Peer(
        'test-peer',
        address=address,
    )

    # If qrcode is not present in the venv, test it fails appropriately.
    with pytest.raises(AttributeError) as exc:
        peer.config.qrcode

    assert 'add the qrcode' in str(exc.value)
