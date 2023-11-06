
import json

from subnet import (
    ip_address,
    ip_network,
    IPv4Address,
    IPv6Address,
)

from .config import Config
from .constants import (
    INTERFACE,
    KEEPALIVE_MINIMUM,
    PORT,
)
from .service import Interface
from .utils import (
    generate_key,
    find_ip_and_subnet,
    public_key as nacl_public_key,
    ClassedSet,
    IPAddressSet,
    IPNetworkSet,
    JSONEncoder,
)


class PeerSet(ClassedSet):
    """
    A set of Peer objects
    """

    def _coerce_value(self, value):
        """
        Bomb if a Peer object is not provided or cannot be coerced from a dict
        """

        if isinstance(value, Peer):
            return value

        if isinstance(value, dict):
            try:
                return Peer(**value)
            except ValueError as exc:
                raise ValueError('Provided value must be an instance of Peer') from exc

        raise ValueError('Provided value must be an instance of Peer')

    def discard_by_description(self, description):
        """
        Discard a peer by description
        """

        try:
            self.remove_by_description(description)
        except KeyError:
            pass

    def remove_by_description(self, description):
        """
        Remove a peer by description
        """

        for peer in self:
            if peer.description == description:
                self.remove(peer)
                return

        raise KeyError(description)

    def discard_by_ip(self, ip):
        """
        Discard a peer by ip
        """

        try:
            self.remove_by_ip(ip)
        except KeyError:
            pass

    def remove_by_ip(self, ip):
        """
        Remove a peer by ip
        """

        chk_ip = ip_address(ip)
        for peer in self:
            if chk_ip in [peer.ipv6, peer.ipv4]:
                self.remove(peer)
                return

        raise KeyError(ip)

    def discard_by_private_key(self, key):
        """
        Discard a peer by private key
        """

        try:
            self.remove_by_private_key(key)
        except KeyError:
            pass

    def remove_by_private_key(self, key):
        """
        Remove a peer by private key
        """

        for peer in self:
            if peer.private_key and peer.private_key == key:
                self.remove(peer)
                return

        raise KeyError(key)

    def discard_by_public_key(self, key):
        """
        Discard a peer by public key
        """

        try:
            self.remove_by_public_key(key)
        except KeyError:
            pass

    def remove_by_public_key(self, key):
        """
        Remove a peer by public key
        """

        for peer in self:
            if peer.public_key == key:
                self.remove(peer)
                return

        raise KeyError(key)


class Peer:  # pylint: disable=too-many-instance-attributes
    """
    The Peer Class

    This is the main type of WireGuard object, representing both a server and a client
    """

    description = None
    _comments = None
    _endpoint = None
    _interface = None
    _ipv6_address = None
    _ipv4_address = None
    _port = None
    _private_key = None
    _public_key = None
    _keepalive = None
    allowed_ips = None
    save_config = None
    dns = None
    pre_up = None
    post_up = None
    pre_down = None
    post_down = None
    _mtu = None
    _table = None

    _config = None
    _service = None
    peers = None

    _config_cls = None
    _service_cls = None

    # pylint: disable=too-many-locals,too-many-branches,too-many-statements,too-many-arguments
    def __init__(self,
                 description,
                 *,
                 comments=None,
                 address=None,
                 endpoint=None,
                 port=None,
                 private_key=None,
                 public_key=None,
                 preshared_key=None,
                 keepalive=None,
                 allowed_ips=None,
                 save_config=None,
                 dns=None,
                 pre_up=None,
                 post_up=None,
                 pre_down=None,
                 post_down=None,
                 interface=None,
                 mtu=None,
                 table=None,
                 peers=None,
                 config_cls=None,
                 service_cls=None,
                 ):

        self.allowed_ips = IPNetworkSet()
        self.dns = IPAddressSet()
        self.peers = PeerSet()
        self.pre_up = []
        self.post_up = []
        self.pre_down = []
        self.post_down = []

        self.description = description
        self.comments = comments

        if not isinstance(address, (list, set, tuple,)):
            address = [address]

        if len(address) > 2:
            raise ValueError(
                'You cannot specify more than 2 IPs for this interface: 1 IPv4 + 1 IPv6')

        # pylint: disable=invalid-name
        for value in address:
            ip, net = find_ip_and_subnet(value)  # pylint: disable=unused-variable
            if ip is None:
                raise ValueError(f"'{value}' does not appear to be an IPv4 or IPv6 address")

            if ip.version == 4:
                if self.ipv4:
                    raise ValueError('Cannot set a 2nd IPv4 address.')

                self.ipv4 = ip

            elif ip.version == 6:
                if self.ipv6:
                    raise ValueError('Cannot set a 2nd IPv6 address.')

                self.ipv6 = ip

        # pylint: enable=invalid-name

        self.endpoint = endpoint

        if private_key is None and public_key is None:
            # If both are not set, then we need to generate a private key
            self._private_key = generate_key()

        else:
            if private_key is not None:
                self.private_key = private_key

            if public_key is not None:
                self.public_key = public_key

        self.preshared_key = preshared_key

        self.port = port
        self.interface = interface
        self.keepalive = keepalive
        self.mtu = mtu
        self.table = table

        if save_config is not None:
            self.save_config = save_config

        # Always add own addresses to allowed IPs, to ensure routing at least makes it that far
        for ip in self.address:  # pylint: disable=invalid-name
            self.allowed_ips.add(ip_network(ip))

        if allowed_ips:
            if isinstance(allowed_ips, (list, set, tuple)):
                self.allowed_ips.extend(allowed_ips)
            else:
                self.allowed_ips.add(allowed_ips)

        if dns:
            if isinstance(dns, (list, set, tuple)):
                self.dns.extend(dns)
            else:
                self.dns.add(dns)

        if pre_up:
            if isinstance(pre_up, (list, set, tuple)):
                self.pre_up.extend(pre_up)
            else:
                self.pre_up.append(pre_up)

        if post_up:
            if isinstance(post_up, (list, set, tuple)):
                self.post_up.extend(post_up)
            else:
                self.post_up.append(post_up)

        if pre_down:
            if isinstance(pre_down, (list, set, tuple)):
                self.pre_down.extend(pre_down)
            else:
                self.pre_down.append(pre_down)

        if post_down:
            if isinstance(post_down, (list, set, tuple)):
                self.post_down.extend(post_down)
            else:
                self.post_down.append(post_down)

        if peers:
            if isinstance(peers, (list, set, tuple)):
                self.peers.extend(peers)
            else:
                self.peers.add(peers)

        self.config_cls = config_cls
        self.service_cls = service_cls

    def __repr__(self):
        """
        A simplistic representation of this object
        """
        return f'<{self.__class__.__name__} iface={self.interface} address={self.address}>'

    def __iter__(self):
        """
        Iterates through this peer's attributes

        Note: the `peers` attribute is handled specially to prevent circular references
              when using `json.dumps()` of Peer objects. Should you desire to dump more
              attributes from each peer, you will need to do so manually.
        """

        peers = []
        for peer in self.peers:
            peers.append({
                'address': peer.address,
                'description': peer.description,
                'public_key': peer.public_key,
            })

        yield from {
            'address': self.address,
            'allowed_ips': self.allowed_ips,
            'description': self.description,
            'dns': self.dns,
            'endpoint': self.endpoint,
            'interface': self.interface,
            'keepalive': self.keepalive,
            'mtu': self.mtu,
            'peers': peers,
            'post_down': self.post_down,
            'post_up': self.post_up,
            'pre_down': self.pre_down,
            'pre_up': self.pre_up,
            'preshared_key': self.preshared_key,
            'private_key': self.private_key,
            'public_key': self.public_key,
            'table': self.table,
        }.items()

    def json(self, **kwargs):
        """
        Produces the JSON output for this object
        """

        if 'cls' not in kwargs or not kwargs['cls']:
            kwargs['cls'] = JSONEncoder

        return json.dumps(self, **kwargs)

    def remove_peer(self, peer, *, bidirectional=True):
        """
        Removes the given peer from this peer

        Default behaviour removes this peer from the given peer as well. Passing
        `bidirectional=False` will only perform the removal on this peer, leaving
        the given peer unchanged.
        """

        # Since we don't care if the peer is already gone, we are using `.discard()`
        # instead of `.remove()` here.
        self.peers.discard(peer)
        if bidirectional:
            peer.peers.discard(self)

    @property
    def comments(self):
        """
        Returns the comments list
        """

        return self._comments

    @comments.setter
    def comments(self, value):
        """
        Sets the comments list
        """

        if not isinstance(value, (list, set, tuple,)):
            value = [value]

        if self._comments is None:
            self._comments = []

        self._comments.extend(value)

    def add_comment(self, value):
        """
        Adds a new comment(s) to the comments list
        """

        if not isinstance(value, (list, set, tuple,)):
            self.comments.append(value)
        else:
            self.comments.extend(value)

    @property
    def port(self):
        """
        Returns the port value
        """

        return self._port

    @port.setter
    def port(self, value):
        """
        Sets the port value
        """

        if value in [None, False]:
            value = PORT
        else:
            value = int(value)
        self._port = value

    @property
    def endpoint(self):
        """
        Returns the endpoint value
        """

        if not isinstance(self._endpoint, str):
            return None

        # This is the easiest sure way to know if the port is already part of the endpoint
        # and will work for domain names, IPv4 and IPv6 addresses
        if self._endpoint.endswith(f':{self.port}'):
            return self._endpoint

        return f'{self._endpoint}:{self.port}'

    @endpoint.setter
    def endpoint(self, value):
        """
        Sets the endpoint value
        """

        self._endpoint = value

    @property
    def interface(self):
        """
        Returns the interface value
        """

        return self._interface

    @interface.setter
    def interface(self, value):
        """
        Sets the interface value
        """

        if value in [None, False]:
            value = INTERFACE
        self._interface = value

    @property
    def ipv4(self):
        """
        Returns the IPv4 address for this object
        """

        return self._ipv4_address

    @ipv4.setter
    def ipv4(self, value):
        """
        Sets the IPv4 address for this connection
        """

        if value is None:
            self._ipv4_address = None
            return

        if not isinstance(value, IPv4Address):
            value = ip_address(value)

        if value.version != 4:
            raise ValueError('Cannot use IPv6 value to set IPv4')

        self._ipv4_address = value

    @property
    def ipv6(self):
        """
        Returns the IPv4 address for this object
        """

        return self._ipv6_address

    @ipv6.setter
    def ipv6(self, value):
        """
        Sets the IPv6 address for this connection
        """

        if value is None:
            self._ipv6_address = None
            return

        if not isinstance(value, IPv6Address):
            value = ip_address(value)

        if value.version != 6:
            raise ValueError('Cannot use IPv4 value to set IPv6')

        self._ipv6_address = value

    @property
    def address(self):
        """
        Returns the address(es) for this peer
        """

        ips = []
        if self.ipv4 is not None:
            ips.append(self.ipv4)

        if self.ipv6 is not None:
            ips.append(self.ipv6)

        return ips

    @property
    def private_key(self):
        """
        Returns the WireGuard private key associated with this object
        """

        if self._private_key is not None:
            return self._private_key

        if self._public_key is not None and self._private_key is None:
            raise AttributeError('Unable to retrieve private key. Public key is set,'
                                 ' and the associated private key was not provided.')

        self._private_key = generate_key()
        return self._private_key

    @private_key.setter
    def private_key(self, value):
        if value is None:
            raise ValueError('Private key cannot be empty!')

        self._private_key = value

    @property
    def public_key(self):
        """
        Returns the WireGuard public key associated with this object
        """

        if self._public_key is not None:
            return self._public_key

        if self._private_key is not None:
            return nacl_public_key(self._private_key)

        raise AttributeError('Neither public key not private key are set!')

    @public_key.setter
    def public_key(self, value):
        """
        Sets the public key for when the private key is unavailable
        """

        if self._private_key is not None and nacl_public_key(self._private_key) != value:
            raise ValueError('Cannot set public key to a value inconsistent with the private key!')

        self._public_key = value

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

            value = max(value, KEEPALIVE_MINIMUM)

        self._keepalive = value

    @property
    def mtu(self):
        """
        returns the mtu value
          WG Default = 1420 (dunno and leave it to automatic for best results)
          if you have to fix mtu depending on outer:
            ipv6 connections require 1280 as minimum (try 1300,1350,1400)
            PPPoE = try 1412 or lower
        """
        return self._mtu

    @mtu.setter
    def mtu(self, value):
        """
        Sets the mtu value
        """
        if value is not None:
            # Check for bool specifically, because bool is a subclass of int
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError('MTU value must be an integer')

            if value < 1280 or value > 1420:
                raise ValueError('MTU value must be in the range 1280-1420')

        self._mtu = value

    @property
    def table(self):
        """
        returns the routing table value
        """
        return self._table

    @table.setter
    def table(self, value):
        """
        Sets the routing table value
        """

        if value is not None:

            try:
                # bool is a subclass of int and can be evaluated in the range condition,
                # _but_ we want to give the correct error message to the user, since
                # setting `Table = True` or `Table = False` would make a WireGuard config
                # file fail to parse correctly. We also don't want to risk `True` becoming
                # `Table = 1` as that is probably not what the user would have wanted.
                if isinstance(value, bool):
                    raise TypeError('Table must not be a boolean')

                if not (0 < value < 253 or 255 < value < (2**31)):
                    raise ValueError('Table must be in the ranges 1-252, 256-(2°31-1)')

            except TypeError as exc:
                # special values allowed (auto=default, off=no route created)
                # ref: https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8
                if value not in ('auto', 'off'):
                    raise ValueError('Table must be "auto", "off" or an integer value') from exc

        self._table = value

    @property
    def config_cls(self):
        """
        Returns the config_cls value
        """

        if not self._config_cls:
            self._config_cls = Config

        return self._config_cls

    @config_cls.setter
    def config_cls(self, value):
        """
        Sets the config_cls value
        """

        if value is not None and not issubclass(value, Config):
            raise ValueError('Provided value must be a subclass of Config')

        self._config_cls = value

    @property
    def service_cls(self):
        """
        Returns the service_cls value
        """

        if not self._service_cls:
            self._service_cls = Interface

        return self._service_cls

    @service_cls.setter
    def service_cls(self, value):
        """
        Sets the service_cls value
        """

        if value is not None and not issubclass(value, Interface):
            raise ValueError('Provided value must be a subclass of Interface')

        self._service_cls = value

    @property
    def config(self):
        """
        Return the wireguard config file for this peer
        """

        if not isinstance(self._config, self.config_cls.__class__):
            self._config = self.config_cls(self)

        return self._config

    @property
    def service(self):
        """
        Returns the service interface for this peer
        """

        if not isinstance(self._service, self.service_cls.__class__):
            self._service = self.service_cls(self.interface)

        return self._service

    def add_nat_traversal(self, outbound_interface):
        """
        Adds appropriate PostUp/PostDown rules when this peer is acting as
        a NAT traversal interface
        """

        # pylint: disable=line-too-long
        post_up = [
            f'iptables -A FORWARD -i %i -o {outbound_interface} -j ACCEPT',
            f'iptables -A FORWARD -i {outbound_interface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
            f'iptables -t nat -A POSTROUTING -o {outbound_interface} -j MASQUERADE',
        ]
        post_down = [
            f'iptables -D FORWARD -i %i -o {outbound_interface} -j ACCEPT',
            f'iptables -D FORWARD -i {outbound_interface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
            f'iptables -t nat -D POSTROUTING -o {outbound_interface} -j MASQUERADE',
        ]
        # pylint: enable=line-too-long

        self.post_up.extend(post_up)
        self.post_down.extend(post_down)
