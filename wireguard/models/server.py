
import os

from .base import WireGuardBase
from .peer import WireGuardPeer


MAX_ADDRESS_RETRIES = 100


class WireGuardServer(WireGuardBase):

    peers = {}
    _peers_config_file = None
    nat_traversal_interface = None

    def __init__(self,
                 name,
                 subnet,
                 address=None,
                 private_key=None,
                 port=None,
                 config_path=None,
                 interface=None,
                 peers_config_file=None,
                 nat_traversal_interface=None,
            ):

        super().__init__(
            name,
            subnet,
            address=address,
            private_key=private_key,
            port=port,
            config_path=config_path,
            interface=interface,
        )

        if peers_config_file:
            self.peers_config_file = peers_config_file
        if nat_traversal_interface:
            self.nat_traversal_interface = nat_traversal_interface

    def __repr__(self):
        """
        A simplistic representation of this object
        """

        return '<WireguardServer name={self.name} iface={self.interface} subnet={self.subnet} address={self.address} nat={self.nat_traversal_interface}>'

    @property
    def peers_config_file(self):
        """
        Returns the peers config file name, if appropriate
        """

        return self._peers_config_file

    @peers_config_file.setter
    def peers_config_file(self, value):
        """
        Sets the peers config file
        """

        if isinstance(value, bool):
            self._peers_config_file = os.path.join(
                self.config_path,
                f'{self.interface}-peers.conf',
            )

        elif not isinstance(value, str):
            raise ValueError('Invalid value for peers_config_file: %s' % value)

        else:
            self._peers_config_file = value
 
    def peer(self,
             name,
             address=None,
             private_key=None,
             port=None,
             routable_ips=None,
             keepalive=None,
        ):

        peer = WireGuardPeer(
            name,
            self.subnet,
            address=address,
            private_key=private_key,
            routable_ips=routable_ips,
            keepalive=keepalive,
            config_path=config_path if config_path else self.config_path,
            interface=interface if interface else self.interface,
            port=self.port,
            endpoint=self.name,
            server_pubkey=self.public_key,
        )

        self.add_peer(peer, allow_ip_change=address is not None)
        return peer

    def add_peer(self, peer, allow_ip_change=False):
        """
        Adds a peer to this server
        """

        if str(peer.address) in self.peers:
            if not allow_ip_change:
                raise ValueError(f'IP address is already used on this server: {peer.address}')

            count = 0
            peer.address = self.subnet.random_ip()

            while str(peer.address) in self.peers:
                if count >= MAX_ADDRESS_RETRIES:
                    raise ValueError('Too many retries to obtain an unused IP address')

                peer.address = self.subnet.random_ip()

        self.peers.update({str(peer.address): peer})

    @property
    def config(self):
        """
        Return the core Wireguard config for this server
        """

        config = f'''

[Interface]
ListenPort = {self.port}
PrivateKey = {self.private_key}
Address = {self.address}/{self.subnet.prefixlen}
SaveConfig = false
'''

        if self.nat_traversal_interface:
            config += f'''

PostUp = iptables -A FORWARD -i %i -o {self.nat_traversal_interface} -j ACCEPT; iptables -A FORWARD -i {self.nat_traversal_interface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -o {self.nat_traversal_interface} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o {self.nat_traversal_interface} -j ACCEPT; iptables -D FORWARD -i {self.nat_traversal_interface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -o {self.nat_traversal_interface} -j MASQUERADE
'''

        if self.peers_config_file:
            config += f'''

PostUp = wg addconf %i {self.peers_config_file}
'''
        else:
            config += self.peers_config

        return config

    @property
    def peers_config(self):
        """
        Returns the peers config for this server
        """

        config = ''
        for peer in self.peers.values():
            config += peer.server_config()

        return config

    @property
    def config_filename(self):
        """
        Returns the full filename of the config file
        """
        return os.path.join(self.config_path, f'{self.interface}.conf')
        
    def write_config(self):
        """
        Writes the server config to the appropriate location
        """

        with open(self.config_filename, 'w') as conffile:
            conffile.write(self.config)

        if self.peers_config_file:
            with open(self.peers_config_file, 'w') as peersfile:
                peersfile.write(self.peers_config)
