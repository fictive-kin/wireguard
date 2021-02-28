
import os

from subnet import ip_network

from .base import WireGuardBase


KEEPALIVE_MINIMUM = 5  # If you really need a keepalive value less than this, override the class


class WireGuardPeer(WireGuardBase):

    endpoint = None
    server_pubkey = None
    _keepalive = None
    _routable_ips = set()

    def __init__(self,
                 name,
                 subnet,
                 address=None,
                 private_key=None,
                 port=None,
                 endpoint=None,
                 routable_ips=None,
                 server_pubkey=None,
                 keepalive=None,
                 config_path=None,
                 interface=None,
                 server=None,
            ):

        super().__init__(
            name,
            subnet,
            address=address,
            port=port,
            private_key=private_key,
            config_path=config_path,
            interface=interface,
            server=server,
        )

        self.server_pubkey = server_pubkey
        self.endpoint = endpoint
        self.keepalive = keepalive

        if not isinstance(routable_ips, list):
            routable_ips = [routable_ips]
        for ip in routable_ips:
            self.add_routable_ip(ip)

    def add_routable_ip(self, ip):
        """
        Adds a routable IP to this config
        """

        ip = ip_network(ip)
        self._routable_ips.add(ip)

    @property
    def routable_ips(self):
        """
        Returns the list of routable IPs for this connection
        """

        routable_ips = self._routable_ips.copy()
        if self.subnet not in self.routable_ips:
            routable_ips.add(self.subnet)

        return routable_ips

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

        if not isinstance(value, int):
            raise ValueError('Keepalive value must be an integer')

        if value < KEEPALIVE_MINIMUM:
            value = KEEPALIVE_MINIMUM

        self._keepalive = value
      
    @property
    def config(self):
        """
            Return the wireguard config file for this gateway
        """

        allowed_ips = join(', ', self.routable_ips)

        return f'''

[Interface]
ListenPort = {self.port}
PrivateKey = {self.private_key}
Address = {self.address}/{self.address.max_prefixlen}
SaveConfig = false

[Peer]
Endpoint = {self.endpoint}:{self.port}
AllowedIPs = {allowed_ips}
PublicKey = {self.server_pubkey}
PersistentKeepalive = {self.keepalive}
'''

    @property
    def serverside_config(self):
        """
        Return the server peer config for this client
        """

        return f'''

[Peer]
# {self.name}
PublicKey = {self.public_key}
AllowedIPs = {self.address}/{self.address.max_prefixlen}
'''

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
