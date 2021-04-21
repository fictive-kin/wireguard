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
        click.echo(iface_peer)
        if verify_connected:
            click.echo(iface_peer.is_connected)

    else:
        for key, obj in iface.stats().items():  # pylint: disable=unused-variable
            click.echo(obj)
            if verify_connected:
                click.echo(obj.is_connected)
