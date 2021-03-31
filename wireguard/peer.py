

from subnet import (
    ip_address,
    ip_network,
)

from .utils import (
    generate_key,
    public_key as nacl_public_key,
    ClassedSet,
    IPAddressSet,
    IPNetworkSet,
)
from .config import Config
from .constants import (
    INTERFACE,
    KEEPALIVE_MINIMUM,
    PORT,
)


class PeerSet(ClassedSet):
    """
    A set of Peer objects
    """

    def _coerce_value(self, value):
        """
        Bomb if a Peer object is not provided
        """

        if not isinstance(value, Peer):
            raise ValueError('Provided value must be an instance of Peer')
        return value


class Peer:  # pylint: disable=too-many-instance-attributes
    """
    The Peer Class

    This is the main type of WireGuard object, representing both a server and a client
    """

    description = None
    _address = None
    _port = None
    _private_key = None
    _public_key = None
    _keepalive = None
    allowed_ips = None
    interface = None
    endpoint = None
    save_config = None
    dns = None
    pre_up = None
    post_up = None
    pre_down = None
    post_down = None

    _config = None
    peers = None

    # pylint: disable=too-many-locals,too-many-branches,too-many-statements
    def __init__(self,
                 description,
                 *,
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
                 interface=INTERFACE,
                 peers=None,
                 config_cls=None,
        ):

        self.allowed_ips = IPNetworkSet()
        self.dns = IPAddressSet()
        self.peers = PeerSet()
        self.pre_up = []
        self.post_up = []
        self.pre_down = []
        self.post_down = []

        self.description = description

        if address is None:
            raise ValueError('Address is required')

        self.address = address
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

        if save_config is not None:
            self.save_config = save_config

        # Always add own address to allowed IPs, to ensure routing at least makes it that far
        self.allowed_ips.add(ip_network(self.address))
        if allowed_ips:
            if isinstance(allowed_ips, (list, set)):
                self.allowed_ips.extend(allowed_ips)
            else:
                self.allowed_ips.add(allowed_ips)
        if dns:
            if isinstance(dns, (list, set)):
                self.dns.extend(dns)
            else:
                self.dns.add(dns)
        if pre_up:
            self.pre_up.append(pre_up)
        if post_up:
            self.post_up.append(post_up)
        if pre_down:
            self.pre_down.append(pre_down)
        if post_down:
            self.post_down.append(post_down)
        if peers:
            if isinstance(peers, (list, set)):
                self.peers.extend(peers)
            else:
                self.peers.add(peers)

        if config_cls is not None:
            self.config(config_cls)

    def __repr__(self):
        """
        A simplistic representation of this object
        """
        return f'<{self.__class__.__name__} iface={self.interface} address={self.address}>'

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
    def address(self):
        """
        Returns the IP address for this object
        """

        if self._address is None:
            raise AttributeError('Address is not set!')

        return self._address

    @address.setter
    def address(self, value):
        """
        Sets the IP address for this connection
        """

        if value is None:
            raise ValueError('Address cannot be empty!')

        self._address = ip_address(value)

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

            if value < KEEPALIVE_MINIMUM:
                value = KEEPALIVE_MINIMUM

        self._keepalive = value

    def config(self, config_cls=Config):
        """
        Return the wireguard config file for this peer
        """

        if self._config is not None and isinstance(self._config, config_cls):
            return self._config

        if not callable(config_cls):
            raise ValueError('Invalid value given for config_cls')

        self._config = config_cls(self)
        return self._config
