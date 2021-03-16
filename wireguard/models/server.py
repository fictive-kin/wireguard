
import os

from subnet import (
    IPv4Address,
    IPv6Address,
    ip_address,
)

from .base import (
    WireGuardBase,
    MAX_ADDRESS_RETRIES,
    MAX_PRIVKEY_RETRIES,
)
from .peer import WireGuardPeer


class WireGuardServer(WireGuardBase):

    peers = []
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
                 inbound_subnets=None,
            ):

        super().__init__(
            name,
            subnet,
            address=address,
            private_key=private_key,
            port=port,
            config_path=config_path,
            interface=interface,
            inbound_subnets=inbound_subnets,
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

    def privkey_exists(self, item):
        """
        Checks a private key against the private keys already used by this server and it's peers
        """

        if item == self.private_key:
            return True

        return item in self.peers_privkeys

    def address_exists(self, item):
        """
        Checks an IP address against the addresses already used by this server and it's peers
        """

        if not isinstance(item, (IPv4Address, IPv6Address)):
            item = ip_address(item)

        if item == self.address:
            return True

        return item in self.peers_addresses

    @property
    def peers_addresses(self):
        if not self.peers:
            return []
        return [peer.address for peer in self.peers]

    @property
    def peers_privkeys(self):
        if not self.peers:
            return []
        return [peer.private_key for peer in self.peers]

    @property
    def peers_pubkeys(self):
        if not self.peers:
            return []
        return [peer.public_key for peer in self.peers]

    @property
    def _default_peers_config_file(self):
        return os.path.join(
                self.config_path,
                f'{self.interface}-peers.conf',
            )

    @property
    def peers_config_file(self):
        """
        Returns the peers config file name, if appropriate
        """

        if isinstance(self._peers_config_file, str):
            return self._peers_config_file
        if self._peers_config_file == True:
            return self._default_peers_config_filename
        return None

    @peers_config_file.setter
    def peers_config_file(self, value):
        """
        Sets the peers config file
        """

        if value == True:
            self._peers_config_file = self._default_peers_config_filename

        elif not isinstance(value, str) and value is not None:
            raise ValueError('Invalid value for peers_config_file: %s' % value)

        else:
            self._peers_config_file = value
 
    def peer(self,
             name,
             address=None,
             private_key=None,
             port=None,
             inbound_subnets=None,
             outbound_subnets=None,
             keepalive=None,
             cls=None,
        ):

        if cls is None:
            cls = WireGuardPeer

        peer = cls(
            name,
            self.subnet,
            address=address,
            private_key=private_key,
            inbound_subnets=inbound_subnets,
            outbound_subnets=outbound_subnets,
            keepalive=keepalive,
            config_path=config_path if config_path else self.config_path,
            interface=interface if interface else self.interface,
            port=self.port,
            endpoint=self.name,
            server_pubkey=self.public_key,
        )

        self.add_peer(peer, allow_ip_change=address is not None)
        return peer

    def add_peer(self, peer, max_address_retries=None, max_privkey_retries=None):
        """
        Adds a peer to this server, checking for a unique IP address + unique private key
        and optionally updating the peer's data to obtain uniqueness
        """

        if (self.unique_address(peer, max_address_retries=max_address_retries) and
            self.unique_privkey(peer, max_privkey_retries=max_privkey_retries)):
            self.peers.append(peer)

        else:
            raise ValueError('Could not add peer to this server. It is not unique.')

    def unique_address(self, peer, max_address_retries=None):
        if peer in self.peers:
            return True

        if max_address_retries is None or max_address_retries == True:
            max_address_retries = MAX_ADDRESS_RETRIES

        if not max_address_retries:
            if self.address_exists(peer.address):
                raise ValueError(f'IP address is already used on this server: {peer.name} ({peer.address})')

        else:
            count = 0
            while self.address_exists(peer.address):
                if count >= max_address_retries:
                    raise ValueError(f'Too many retries to obtain an unused IP address: {peer.name}')

                peer.address = self.subnet.random_ip()
                count += 1

        return True

    def unique_privkey(self, peer, max_privkey_retries=None):
        if peer in self.peers:
            return True

        if max_privkey_retries is None or max_privkey_retries == True:
            max_privkey_retries = MAX_PRIVKEY_RETRIES

        if not max_privkey_retries:
            if self.privkey_exists(peer.private_key):
                raise ValueError(f'Private key is already used on this server: {peer.name}')

        else:
            count = 0
            while self.privkey_exists(peer.private_key):
                if count >= max_privkey_retries:
                    raise ValueError(f'Too many retries to obtain an unused private key: {peer.name}')

                peer.private_key = generate_key()
                count += 1

        return True

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

PostUp = iptables -A FORWARD -i %i -o {self.nat_traversal_interface} -j ACCEPT
PostUp = iptables -A FORWARD -i {self.nat_traversal_interface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o {self.nat_traversal_interface} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o {self.nat_traversal_interface} -j ACCEPT
PostDown = iptables -D FORWARD -i {self.nat_traversal_interface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o {self.nat_traversal_interface} -j MASQUERADE
'''

        if self.peers_config_file:
            config += f'''

PostUp = wg addconf %i {self.peers_config_file}
'''
        else:
            config += self.peers_config()

        return config

    def peers_config(self):
        """
        Returns the peers config for this server
        """

        config = ''
        for peer in self.peers:
            config += peer.serverside_config()

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
            conffile.write(self.config())

        if self.peers_config_file:
            with open(self.peers_config_file, 'w') as peersfile:
                peersfile.write(self.peers_config())
