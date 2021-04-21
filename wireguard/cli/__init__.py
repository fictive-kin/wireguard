"""
wireguard.cli

Command line interaction helpers for apps using Click
"""

# pylint: disable=too-many-arguments,unnecessary-pass

import click

from .config import cli as config_cli
from .service import cli as service_cli


@click.group()
def cli():
    """Commands to interact with WireGuard"""
    pass


cli.add_command(config_cli, name='config')
cli.add_command(service_cli, name='service')

if __name__ == "__main__":
    cli()  # pylint: disable=no-value-for-parameter
