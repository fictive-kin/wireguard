"""
wireguard.cli.config

Interaction with the config files
"""

# pylint: disable=too-many-arguments,unnecessary-pass

import os

import click

from wireguard import Server


@click.group()
def cli():
    """Commands to interact with WireGuard"""
    pass


@cli.command()
@click.option('-e', '--endpoint', help='The public domain name for this server', prompt=True)
@click.option('-s', '--subnet', help='The subnet that this server should use for the VPN',
              prompt=True)
@click.option('-a', '--address', help='The IP that the server should use within the VPN')
@click.option('-P', '--private-key', help='The private key to use for the server')
@click.option('-p', '--port', help='The port that the server should bind to')
@click.option('-i', '--interface', help='The interface name for this VPN')
@click.option('-t', '--nat-traversal-interface',
              help='If using NAT for this connection, the interface name to route connections'
                   ' through')
@click.option('-w', '--write', help='Write out the config file', is_flag=True)
def server(endpoint,
           subnet,
           address=None,
           private_key=None,
           port=None,
           interface=None,
           nat_traversal_interface=None,
           write=False,
    ):
    """
    Display, and optionally write, a WireGuard basic server config
    """

    obj = Server(
        endpoint,
        subnet,
        endpoint=endpoint,
        address=address,
        private_key=private_key,
        port=port,
        interface=interface,
    )
    if nat_traversal_interface:
        obj.add_nat_traversal(nat_traversal_interface)

    click.echo(obj.config)

    if write:
        if os.path.isfile(obj.config.full_path):
            if not click.prompt(f'{obj.config.full_path} exists! Overwrite? [y/N]'):
                click.Abort()
        if os.path.isfile(obj.config.peers_full_path):
            if not click.prompt(f'{obj.config.peers_full_path} exists! Overwrite? [y/N]'):
                click.Abort()

        obj.config.write()


@cli.command()
@click.option('-n', '--name', help='An indentifiable name for this peer', prompt=True)
@click.option('-s', '--subnet',
              help='The subnet that this server should use for the VPN', prompt=True)
@click.option('-a', '--address', help='The IP that the peer should use within the VPN')
@click.option('-P', '--private-key', help='The private key to use for the peer')
@click.option('-p', '--port', help='The port that the server is listening on')
@click.option('-e', '--endpoint', help='The public domain name for the VPN server', prompt=True)
@click.option('-S', '--server-pubkey', help='The public key of the VPN server', prompt=True)
@click.option('-r', '--routable-ip',
              help='An additional IP range that should route through the VPN', multiple=True)
@click.option('-k', '--keepalive',
              help='How often the peer should contact the server, in seconds', type=int)
@click.option('-K', '--preshared-key',
              help='A pre-shared key for this peer, for post-quantum resistance')
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
         interface=None,
         write=False,
    ):
    """
    Display, and optionally write, a WireGuard peer config
    """

    throwaway_server = Server(
        endpoint,
        subnet,
        endpoint=endpoint,
        public_key=server_pubkey,
        port=port,
        allowed_ips=routable_ip,
    )

    obj = throwaway_server.peer(
        name,
        address=address,
        private_key=private_key,
        port=port,
        preshared_key=preshared_key,
        keepalive=keepalive,
        interface=interface,
    )

    click.echo(obj.config)

    if write:
        if os.path.isfile(obj.config.full_path):
            if not click.prompt(f'{obj.config.full_path} exists! Overwrite? [y/N]'):
                click.Abort()

        obj.config.write()


if __name__ == "__main__":
    cli()  # pylint: disable=no-value-for-parameter
