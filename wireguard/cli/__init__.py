"""
wireguard.cli

Command line interaction helpers for apps using Click
"""

import os
import sys

import click

from wireguard import WireGuardServer
from wireguard import WireGuardPeer


@click.group()
def cli():
    """Commands to interact with WireGuard"""
    pass


@cli.command()
@click.option('-n', '--name', help='The public domain name for this server', prompt=True)
@click.option('-s', '--subnet', help='The subnet that this server should use for the VPN', prompt=True)
@click.option('-a', '--address', help='The IP that the server should use within the VPN')
@click.option('-P', '--private-key', help='The private key to use for the server')
@click.option('-p', '--port', help='The port that the server should bind to')
@click.option('-c', '--config-path', help='The path to the config files')
@click.option('-i', '--interface', help='The interface name for this VPN')
@click.option('-f', '--peers-config-file', help='The config filename it peers should be in a seperate file, or True to use the default name')
@click.option('-t', '--nat-traversal-interface', help='If using NAT for this connection, the interface name to route connections through')
@click.option('-w', '--write', help='Write out the config file', is_flag=True)
def server(name,
           subnet,
           address=None,
           private_key=None,
           port=None,
           config_path=None,
           interface=None,
           peers_config_file=None,
           nat_traversal_interface=None,
           write=False,
    ):
    """
    Display, and optionally write, a WireGuard basic server config
    """

    server = WireGuardServer(
        name,
        subnet,
        address=address,
        private_key=private_key,
        port=port,
        config_path=config_path,
        interface=interface,
        peers_config_file=peers_config_file,
        nat_traversal_interface=nat_traversal_interface,
    )

    click.echo(server.config)
    if server.peers_config_file:
        click.echo(server.peers_config)

        if write:
            if os.path.is_file(server.peers_config_file):
               if not click.prompt(f'{server.peers_config_file} exists! Overwrite? [y/N]'):
                   click.Abort()

    if write:
        if os.path.is_file(server.config_filename):
           if not click.prompt(f'{server.config_filename} exists! Overwrite? [y/N]'):
               click.Abort()

        server.write_config()


@cli.command()
@click.option('-n', '--name', help='An indentifiable name for this peer', prompt=True)
@click.option('-s', '--subnet', help='The subnet that this server should use for the VPN', prompt=True)
@click.option('-a', '--address', help='The IP that the peer should use within the VPN')
@click.option('-P', '--private-key', help='The private key to use for the peer')
@click.option('-p', '--port', help='The port that the server is listening on')
@click.option('-e', '--endpoint', help='The public domain name for the VPN server', prompt=True)
@click.option('-S', '--server-pubkey', help='The public key of the VPN server', prompt=True)
@click.option('-r', '--routable-ip', help='An addition IP range that should route through the VPN', multiple=True)
@click.option('-k', '--keepalive', help='How often the peer should contact the server, in seconds', type=int)
@click.option('-K', '--preshared-key', help='A pre-shared key for this peer, for post-quantum resistance')
@click.option('-c', '--config-path', help='The path to the config files')
@click.option('-i', '--interface', help='The interface name for this VPN')
@click.option('-w', '--write', help='Write out the config file', is_flag=True)
def peer(name,
         subnet,
         address=None,
         private_key=None,
         port=None,
         endpoint=None,
         server_pubkey=None,
         routable_ip=None,
         preshared_key=None,
         keepalive=None,
         config_path=None,
         interface=None,
         write=False,
    ):
    """
    Display, and optionally write, a WireGuard peer config
    """

    peer = WireGuardPeer(
        name,
        subnet,
        address=address,
        private_key=private_key,
        port=port,
        endpoint=endpoint,
        server_pubkey=server_pubkey,
        routable_ips=routable_ip,
        preshared_key=preshared_key,
        keepalive=keepalive,
        config_path=config_path,
        interface=interface,
    )

    click.echo(peer.config)

    if write:
        if os.path.is_file(peer.config_filename):
           if not click.prompt(f'{peer.config_filename} exists! Overwrite? [y/N]'):
               click.Abort()

        peer.write_config()


if __name__ == "__main__":
    cli()  # pylint: disable=no-value-for-parameter
