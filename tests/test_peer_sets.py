

import pytest

from wireguard import (
    Peer,
    Server,
)
from wireguard.peer import (
    PeerSet,
)


def test_peer_set_removes():

    server = Server(
        'server1',
        subnet='192.168.0.1/24',
    )

    peer1 = server.peer('peer1')
    peer2 = server.peer('peer2')
    peer3 = server.peer('peer3')
    peer4 = server.peer('peer4')
    peer5 = server.peer('peer5')

    with pytest.raises(KeyError):
        server.peers.remove_by_description('peer6')

    with pytest.raises(KeyError):
        server.peers.remove_by_ip('10.10.10.10')

    with pytest.raises(KeyError):
        server.peers.remove_by_private_key('wBdB54t1rUBQ3mc0OvKdhzzaD9MvKGrshLQyHw5CN1A=')

    with pytest.raises(KeyError):
        server.peers.remove_by_public_key('m5Tp7TvZOQYUnfmxsRN9TsmfEi5jssWpyjs5X6OP9k8=')

    server.peers.remove(peer3)
    for peer in server.peers:
        assert peer.description != 'peer3'
    assert len(server.peers) == 4

    server.peers.remove_by_description('peer2')
    for peer in server.peers:
        assert peer.description != 'peer2'
    assert len(server.peers) == 3

    server.peers.remove_by_ip(peer1.ipv4)
    for peer in server.peers:
        assert peer.description != 'peer1'
        assert peer.ipv4 != peer1.ipv4
    assert len(server.peers) == 2

    server.peers.remove_by_private_key(peer4.private_key)
    for peer in server.peers:
        assert peer.description != 'peer4'
        assert peer.private_key != peer4.private_key
    assert len(server.peers) == 1

    server.peers.remove_by_public_key(peer5.public_key)
    for peer in server.peers:
        assert peer.description != 'peer5'
        assert peer.public_key != peer5.public_key
    assert len(server.peers) == 0


def test_peer_set_discards():

    server = Server(
        'server2',
        subnet='192.168.0.1/24',
    )

    peer1 = server.peer('peer1')
    peer2 = server.peer('peer2')
    peer3 = server.peer('peer3')
    peer4 = server.peer('peer4')
    peer5 = server.peer('peer5')

    server.peers.discard_by_description('peer6')
    server.peers.discard_by_ip('10.10.10.10')
    server.peers.discard_by_private_key('wBdB54t1rUBQ3mc0OvKdhzzaD9MvKGrshLQyHw5CN1A=')
    server.peers.discard_by_public_key('m5Tp7TvZOQYUnfmxsRN9TsmfEi5jssWpyjs5X6OP9k8=')

    server.peers.discard(peer4)
    for peer in server.peers:
        assert peer.description != 'peer4'
    assert len(server.peers) == 4

    server.peers.discard_by_description('peer5')
    for peer in server.peers:
        assert peer.description != 'peer5'
    assert len(server.peers) == 3

    server.peers.discard_by_ip(peer2.ipv4)
    for peer in server.peers:
        assert peer.description != 'peer2'
        assert peer.ipv4 != peer2.ipv4
    assert len(server.peers) == 2

    server.peers.discard_by_private_key(peer3.private_key)
    for peer in server.peers:
        assert peer.description != 'peer3'
        assert peer.private_key != peer3.private_key
    assert len(server.peers) == 1

    server.peers.discard_by_public_key(peer1.public_key)
    for peer in server.peers:
        assert peer.description != 'peer1'
        assert peer.public_key != peer1.public_key
    assert len(server.peers) == 0


def test_peer_bidirectional_removal():

    server = Server(
        'server3',
        subnet='192.168.0.1/24',
    )

    peer1 = server.peer('peer1')
    peer2 = server.peer('peer2')
    peer3 = server.peer('peer3')
    peer4 = server.peer('peer4')
    peer5 = server.peer('peer5')

    assert len(server.peers) == 5

    assert len(peer4.peers) == 1
    server.remove_peer(peer4)
    assert len(peer4.peers) == 0
    assert len(server.peers) == 4

    assert len(peer3.peers) == 1
    server.remove_peer(peer3, bidirectional=False)
    assert len(peer3.peers) == 1
    assert len(server.peers) == 3

    assert len(peer3.peers) == 1
    peer3.remove_peer(server)
    assert len(peer3.peers) == 0
    assert len(server.peers) == 3  # was already removed in the previous block

    assert len(peer5.peers) == 1
    peer5.remove_peer(server)
    assert len(peer5.peers) == 0
    assert len(server.peers) == 2

    assert len(peer1.peers) == 1
    peer1.remove_peer(server, bidirectional=False)
    assert len(peer1.peers) == 0
    assert len(server.peers) == 2
