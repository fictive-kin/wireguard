
from subnet import (
    IPv4Address,
    IPv6Address,
    ip_address,
)

from .constants import (
    MAX_ADDRESS_RETRIES,
    MAX_PRIVKEY_RETRIES,
)
from .config import ServerConfig
from .peer import Peer
from .utils import generate_key, public_key, find_ip_and_subnet


INHERITABLE_OPTIONS = [
    'dns',
    'interface',
    'keepalive',
    'mtu',
    'port',
    'preshared_key',
]


class Server(Peer):
    """
    The WireGuard Server

    While not required to have a server<->client setup, this class simplifies doing so
    """

    ipv4_subnet = None
    ipv6_subnet = None

    def __init__(self,
                 description,
                 subnet,
                 **kwargs
            ):  # pylint: disable=too-many-branches

        if not isinstance(subnet, (list, set, tuple,)):
            subnet = [subnet]

        if len(subnet) > 2:
            raise ValueError('You cannot set more than 2 core subnets: 1 IPv4 + 1 IPv6. '
                             'Use AllowedIPs instead.')

        addresses_from_subnets = []
        for value in subnet:
            ip, net = find_ip_and_subnet(value)  # pylint: disable=invalid-name

            if net is None:
                raise ValueError(f"'{value}' does not appear to be an IPv4 or IPv6 network")

            if ip is not None:
                if 'address' in kwargs and kwargs['address'] is not None:
                    raise ValueError(
                        'You cannot provide both an address AND a subnet with host bits set!'
                    )

                addresses_from_subnets.append(ip)

            if net.prefixlen == net.max_prefixlen:
                raise ValueError('You cannot use an IPv4 `/32` subnet, nor an IPv6 '
                                 '`/128` subnet as that only gives you 1 IP address '
                                 'to use, and therefore you cannot have any peers!')

            if net.version == 4:
                if self.ipv4_subnet:
                    raise ValueError('You cannot set 2 IPv4 core subnets.')

                self.ipv4_subnet = net

            elif net.version == 6:
                if self.ipv6_subnet:
                    raise ValueError('You cannot set 2 IPv6 core subnets.')

                self.ipv6_subnet = net

        if 'address' not in kwargs:
            if addresses_from_subnets:
                kwargs.update({'address': addresses_from_subnets})
            else:
                kwargs.update({'address': self.unique_address()})

        if 'config_cls' not in kwargs:
            kwargs.update({'config_cls': ServerConfig})

        if 'allowed_ips' not in kwargs or not kwargs['allowed_ips']:
            kwargs.update({'allowed_ips': []})
        elif not isinstance(kwargs['allowed_ips'], list):
            kwargs['allowed_ips'] = list(kwargs['allowed_ips'])

        if self.ipv4_subnet:
            kwargs['allowed_ips'].append(self.ipv4_subnet)
        if self.ipv6_subnet:
            kwargs['allowed_ips'].append(self.ipv6_subnet)

        super().__init__(
            description,
            **kwargs
        )

    def __repr__(self):
        """
        A simplistic representation of this object
        """

        return (f'<{self.__class__.__name__} iface={self.interface} ipv4={self.ipv4_subnet} '
                f'ipv6={self.ipv6_subnet} address={self.address}>')

    def __iter__(self):
        """
        Iterates through this server's useful attributes
        """

        subnets = []
        if self.ipv4_subnet:
            subnets.append(self.ipv4_subnet)
        if self.ipv6_subnet:
            subnets.append(self.ipv6_subnet)

        yield from {'subnet': subnets}.items()
        yield from super().__iter__()

    def pubkey_exists(self, item):
        """
        Checks a public key against the public keys already used by this server and it's peers
        """

        if item == self.public_key:
            return True

        return item in self.peers_pubkeys

    def address_exists_ipv4(self, item):
        """
        Checks an IPv4 address against the addresses already used by this server and it's peers
        """

        if not isinstance(item, IPv4Address):
            item = ip_address(item)

        if item == self.ipv4:
            return True

        return item in self.peers_addresses_ipv4

    def address_exists_ipv6(self, item):
        """
        Checks an IPv6 address against the addresses already used by this server and it's peers
        """

        if not isinstance(item, IPv6Address):
            item = ip_address(item)

        if item == self.ipv6:
            return True

        return item in self.peers_addresses_ipv6

    @property
    def peers_addresses_ipv4(self):
        """
        Returns all the IPv4 addresses for the peers attached to this server
        """

        if not self.peers:
            return []
        return [peer.ipv4 for peer in self.peers]

    @property
    def peers_addresses_ipv6(self):
        """
        Returns all the IPv6 addresses for the peers attached to this server
        """

        if not self.peers:
            return []
        return [peer.ipv6 for peer in self.peers]

    @property
    def peers_pubkeys(self):
        """
        Returns all the public keys for the peers attached to this server
        """

        if not self.peers:
            return []
        return [peer.public_key for peer in self.peers]

    def unique_address(self, max_address_retries=None):
        """
        Return unused addresses from this server's subnets (1 IPv4 + 1 IPv6, if applicable)
        """

        addresses = []

        if self.ipv4_subnet:
            addresses.append(self.unique_address_ipv4(max_address_retries))

        if self.ipv6_subnet:
            addresses.append(self.unique_address_ipv6(max_address_retries))

        return addresses

    def unique_address_ipv4(self, max_address_retries=None):
        """
        Return an unused address from this server's IPv4 subnet
        """

        if max_address_retries in [None, True]:
            max_address_retries = MAX_ADDRESS_RETRIES

        address = self.ipv4_subnet.random_ip()
        tries = 0

        while self.address_exists_ipv4(address):
            if tries >= max_address_retries:
                raise ValueError('Too many retries to obtain an unused IPv4 address')

            address = self.ipv4_subnet.random_ip()
            tries += 1

        return address

    def unique_address_ipv6(self, max_address_retries=None):
        """
        Return an unused address from this server's IPv6 subnet
        """

        if max_address_retries in [None, True]:
            max_address_retries = MAX_ADDRESS_RETRIES

        address = self.ipv6_subnet.random_ip()
        tries = 0

        while self.address_exists_ipv6(address):
            if tries >= max_address_retries:
                raise ValueError('Too many retries to obtain an unused IPv6 address')

            address = self.ipv6_subnet.random_ip()
            tries += 1

        return address

    def unique_privkey(self, max_privkey_retries=None):
        """
        Returns a private key that is not already in use among this server's peers
        """

        if max_privkey_retries in [None, True]:
            max_privkey_retries = MAX_PRIVKEY_RETRIES

        private_key = generate_key()
        tries = 0

        while self.pubkey_exists(public_key(private_key)):
            if tries >= max_privkey_retries:
                raise ValueError('Too many retries to obtain an unique private key')

            private_key = generate_key()
            tries += 1

        return private_key

    def peer(self,
             description,
             *,
             peer_cls=None,
             **kwargs
        ):
        """
        Returns a peer that is prepopulated with values appropriate for this server
        """

        if peer_cls in [None, False]:
            peer_cls = Peer
        elif not callable(peer_cls):
            raise ValueError('Invalid value given for peer_cls')

        if 'address' not in kwargs:
            kwargs.update({'address': self.unique_address()})

        # These are keys that should be propagated from the server to a remote peer, only
        # if they are not already being explicitly set at peer creation
        for key in INHERITABLE_OPTIONS:
            if key not in kwargs:
                kwargs.update({key: getattr(self, key, None)})
        if kwargs['mtu'] != self.mtu:
            raise ValueError('MTU cannot be different between different peers')

        peer = peer_cls(
            description,
            **kwargs
        )

        self.add_peer(
            peer,
            max_address_retries=(kwargs.get('address') is None),
            max_privkey_retries=(kwargs.get('private_key') is None),
        )
        return peer

    def add_peer(self, peer, max_address_retries=None, max_privkey_retries=None):
        """
        Adds a peer to this server, checking for a unique IP address + unique private key
        and optionally updating the peer's data to obtain uniqueness
        """

        if self.ipv4_subnet and peer.ipv4:
            if self.address_exists_ipv4(peer.ipv4):
                try:
                    if max_address_retries in [False, 0]:
                        raise ValueError('Not allowed to change the peer IP address due to'
                                         ' max_address_retries=False (or 0)')
                    peer.ipv4 = self.unique_address_ipv4(max_address_retries)
                except ValueError as exc:
                    raise ValueError(
                        'Could not add peer to this server. It is not unique.') from exc

        if self.ipv6_subnet and peer.ipv6:
            if self.address_exists_ipv6(peer.ipv6):
                try:
                    if max_address_retries in [False, 0]:
                        raise ValueError('Not allowed to change the peer IP address due to'
                                         ' max_address_retries=False (or 0)')
                    peer.ipv6 = self.unique_address_ipv6(max_address_retries)
                except ValueError as exc:
                    raise ValueError(
                        'Could not add peer to this server. It is not unique.') from exc

        if self.pubkey_exists(peer.public_key):
            try:
                if max_privkey_retries in [False, 0]:
                    raise ValueError('Not allowed to change the peer private key due to'
                                     ' max_privkey_retries=False (or 0)')
                peer.private_key = self.unique_privkey(max_privkey_retries)
            except ValueError as exc:
                raise ValueError(
                        'Could not add peer to this server. It is not unique.') from exc

        peer.peers.add(self)  # This server needs to be a peer of the new peer
        self.peers.add(peer)  # The peer needs to be attached to this server
