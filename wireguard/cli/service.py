"""
wireguard.cli.service

Interaction with the system's wireguard service
"""

# pylint: disable=too-many-arguments,unnecessary-pass

import click

try:
    from hurry.filesize import size as human_size
    HAS_HURRY_FILESIZE = True
except ImportError:
    HAS_HURRY_FILESIZE = False

from wireguard.service import Interface, InterfacePeer


def size(filesize, convert_from_bytes=False):
    """
    Convert to a appropriate file size string for display
    """
    if convert_from_bytes and HAS_HURRY_FILESIZE:
        return human_size(int(filesize))

    return str(filesize) + 'B'


def is_connected_repr(iface_peer, human_readable):
    """Returns a string representation of the peer object including connection state"""

    iface = iface_peer.interface
    name = iface_peer.peer
    tx = size(iface_peer.tx, human_readable)  # pylint: disable=invalid-name
    rx = size(iface_peer.rx, human_readable)  # pylint: disable=invalid-name
    state = iface_peer.is_connected

    return f'<InterfacePeer interface={iface} peer={name} tx={tx} rx={rx} connected={state}>'


@click.group()
def cli():
    """Commands to interact with WireGuard"""
    pass


@cli.command()
@click.argument('interface')
@click.option('-p', '--peer', help='The peer to limit stats to')
@click.option('-v', '--verify-connected', is_flag=True, default=False,
              help='Ping the peer to verify connectivity')
@click.option('-h', '--human-readable', is_flag=True, default=False,
              help='Render rx/tx bytes in KB/MB/etc, as appropriate')
def stats(interface, peer=None, verify_connected=False, human_readable=False):
    """
    Display the stats for the given interface
    """

    iface = Interface(interface)
    if peer:
        iface_peer = iface.stats().get(peer, InterfacePeer(interface, peer))
        if verify_connected:
            click.echo(is_connected_repr(iface_peer, human_readable))
        else:
            click.echo(iface_peer)

    else:
        for key, obj in iface.stats().items():  # pylint: disable=unused-variable
            if verify_connected:
                click.echo(is_connected_repr(obj, human_readable))
            else:
                click.echo(obj)
