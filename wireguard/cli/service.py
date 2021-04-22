"""
wireguard.cli.service

Interaction with the system's wireguard service
"""

# pylint: disable=too-many-arguments,unnecessary-pass

import click

from wireguard.service import Interface, InterfacePeer


@click.group()
def cli():
    """Commands to interact with WireGuard"""
    pass


@cli.command()
@click.argument('interface')
@click.option('-p', '--peer', help='The peer to limit stats to')
@click.option('-v', '--verify-connected', is_flag=True, default=False,
              help='Ping the peer to verify connectivity')
def stats(interface, peer=None, verify_connected=False):
    """
    Display the stats for the given interface
    """

    iface = Interface(interface)
    if peer:
        iface_peer = iface.stats().get(peer, InterfacePeer(interface, peer))
        if verify_connected:
            click.echo(
                '<InterfacePeer interface={} peer={} tx={} rx={} connected={}>'.format(
                    iface_peer.interface,
                    iface_peer.peer,
                    iface_peer.tx,
                    iface_peer.rx,
                    iface_peer.is_connected))
        else:
            click.echo(iface_peer)

    else:
        for key, obj in iface.stats().items():  # pylint: disable=unused-variable
            if verify_connected:
                click.echo(
                    '<InterfacePeer interface={} peer={} tx={} rx={} connected={}>'.format(
                        obj.interface,
                        obj.peer,
                        obj.tx,
                        obj.rx,
                        obj.is_connected))
            else:
                click.echo(obj)
