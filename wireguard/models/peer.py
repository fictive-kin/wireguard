
import os

from subnet import ip_network, IPv4Network, IPv6Network

from .base import (
    WireGuardBase,
    KEEPALIVE_MINIMUM,
)
from ..utils import generate_key


class WireGuardPeer(WireGuardBase):

    endpoint = None
    server_pubkey = None
    _preshared_key = None
    _keepalive = None
    _outbound_subnets = set()
    _inbound_subnets = set()

    server = None

    def __init__(self,
                 name,
                 subnet=None,
                 address=None,
                 private_key=None,
                 port=None,
                 endpoint=None,
                 outbound_subnets=None,
                 inbound_subnets=None,
                 server_pubkey=None,
                 preshared_key=None,
                 keepalive=None,
                 config_path=None,
                 interface=None,
                 server=None,
            ):

        if not subnet:
            if server and server.subnet:
                subnet = server.subnet
            else:
                raise ValueError(
                    'When a subnet is not directly specified, a server must be provided.')


        super().__init__(
            name,
            subnet,
            address=address,
            port=port,
            private_key=private_key,
            config_path=config_path,
            interface=interface,
            inbound_subnets=inbound_subnets,
        )

        if server:
            self.server = server

        self.endpoint = endpoint
        self.server_pubkey = server_pubkey
        self.preshared_key = preshared_key

        if keepalive is not None:
            self.keepalive = keepalive

        self.outbound_subnets = outbound_subnets

    def add_outbound_subnet(self, ips):
        """
        Adds subnets that should route to the server

        IP address objects/strings will automatically be set to `/32` or `/128` subnets
        by `ip_network()` when no netmask is specified. No special handling is required.

        While this will restrict the routing to unique subnets, it will not merge
        adjacent subnets into a single subnet value, even when possible.
        """

        if not isinstance(ips, list):
            ips = [ips]
        for ip in ips:
            if not isinstance(ip, (IPv4Network, IPv6Network)):
                ip = ip_network(ip)
            self._outbound_subnets.add(ip)

    @property
    def outbound_subnets(self):
        """
        Returns the subnets that should route to the server
        """

        subnets = self._outbound_subnets.copy()
        if self.subnet not in subnets:
            subnets.add(self.subnet)

        if self.server:
            if (self.subnet != self.server.subnet and self.server.subnet not in subnets):
                subnets.add(self.server.subnet)

        return subnets

    @outbound_subnets.setter
    def outbound_subnets(self, value):
        """
        Set the subnets that should route to the server
        """

        self._outbound_subnets = set()
        if value is not None:
            if not isinstance(value, list):
                value = [value]

            for ip in value:
                self.add_outbound_subnet(ip)

    @property
    def preshared_key(self):
        """
        Returns the preshared_key value
        """
        return self._preshared_key

    @preshared_key.setter
    def preshared_key(self, value):
        """
        Sets the preshared_key value
        """

        if not isinstance(value, str) and value:
            value = generate_key()

        self._preshared_key = value

    @property
    def keepalive(self):
        """
        Returns the keepalive value
        """
        return self._keepalive

    @keepalive.setter
    def keepalive(self, value):
        """
        Sets the keepalive value
        """

        if value is not None:
            if not isinstance(value, int):
                raise ValueError('Keepalive value must be an integer')

            if value < KEEPALIVE_MINIMUM:
                value = KEEPALIVE_MINIMUM

        self._keepalive = value

    def config(self):
        """
            Return the wireguard config file for this peer
        """

        allowed_ips = ', '.join([str(subnet) for subnet in self.outbound_subnets])

        config = f'''

[Interface]
ListenPort = {self.port}
PrivateKey = {self.private_key}
Address = {self.address}/{self.address.max_prefixlen}

[Peer]
Endpoint = {self.endpoint}:{self.port}
AllowedIPs = {allowed_ips}
PublicKey = {self.server_pubkey}
'''

        if self.keepalive:
            config += f'''
PersistentKeepalive = {self.keepalive}
'''
        if self.preshared_key:
            config += f'''
PresharedKey = {self.preshared_key}
'''

        return config

    def serverside_config(self):
        """
        Return the server peer config for this client
        """

        allowed_ips = ', '.join([str(subnet) for subnet in self.inbound_subnets])
        return f'''

[Peer]
# {self.name}
PublicKey = {self.public_key}
AllowedIPs = {allowed_ips}
'''

        if self.preshared_key:
            config += f'''
PresharedKey = {self.preshared_key}
'''

        return config

    @property
    def config_filename(self):
        """
        Returns the full filename of the config file
        """
        return os.path.join(self.config_path, f'{self.interface}.conf')

    def write_config(self):
        """
        Writes the config file
        """

        with open(self.config_filename, 'w') as conffile:
            conffile.write(self.config)
