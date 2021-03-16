

from subnet import ip_network, ip_address

from ..utils import generate_key, public_key


# If you really need a keepalive value less than this, you might want to rethink your life
KEEPALIVE_MINIMUM = 5

MAX_ADDRESS_RETRIES = 100
MAX_PRIVKEY_RETRIES = 10  # If we can't get an used privkey in 10 tries, we're screwed

DEFAULT_CONFIG_PATH = '/etc/wireguard'
DEFAULT_INTERFACE = 'wg0'
DEFAULT_PORT = 51820


class WireGuardBase:

    name = None
    subnet = None
    _address = None
    port = None
    _private_key = None
    config_path = None
    interface = None
    _inbound_subnets = set()

    def __init__(self,
                 name,
                 subnet,
                 address=None,
                 port=None,
                 private_key=None,
                 config_path=None,
                 interface=None,
                 inbound_subnets=None,
        ):

        self.name = name
        self.subnet = ip_network(subnet)

        if address is None:
            self.address = self.subnet.random_ip()

        else:
            self.address = address

        if private_key:
            self.private_key = private_key

        self.port = int(port) if port is not None else DEFAULT_PORT
        self.config_path = config_path if config_path is not None else DEFAULT_CONFIG_PATH
        self.interface = interface if interface is not None else DEFAULT_INTERFACE

        self.inbound_subnets = inbound_subnets

    def add_inbound_subnet(self, ip):
        """
        Adds subnets that the remote peer should route to this peer

        IP address objects/strings will automatically be set to `/32` or `/128` subnets
        by `ip_network()` when no netmask is specified. No special handling is required.

        While this will restrict the routing to unique subnets, it will not merge
        adjacent subnets into a single subnet value, even when possible.
        """

        if not isinstace(ip, list):
            ip = [ip]
        for ip in ips:
            if not isinstance(ip, (IPv4Network, IPv6Network)):
                ip = ip_network(ip)
            self._inbound_subnets.add(ip)

    @property
    def inbound_subnets(self):
        """
        Returns the subnets that the remote peer should route to this peer
        """

        subnets = self._inbound_subnets.copy()
        local_subnet = ip_network(self.address)
        if local_subnet not in subnets:
            subnets.add(local_subnet)

        return subnets

    @inbound_subnets.setter
    def inbound_subnets(self, value):
        """
        Set the subnets that the remote peer should route to this peer
        """

        self._inbound_subnets = set()
        if value is not None:
            if not isinstance(value, list):
                value = [value]

            for ip in value:
                self.add_inbound_subnet(ip)

    @property
    def address(self):
        """
        Returns the IP address for this object
        """

        return self._address

    @address.setter
    def address(self, value):
        """
        Sets the IP address for this connection
        """

        value = ip_address(value)
        if value not in self.subnet:
            raise InvalidIPAddressForSubnet(
                f'"{address}" is outside of specified subnet: {self.subnet}'
            )

        self._address = value

    @property
    def private_key(self):
        """
        Returns the WireGuard private key associated with this object
        """

        if self._private_key is not None:
            return self._private_key

        self._private_key = generate_key()
        return self._private_key

    @private_key.setter
    def private_key(self, value):
        if value is None:
            raise ValueError('Private key cannot be empty')

        self._private_key = value

    @property
    def public_key(self):
        """
        Returns the WireGuard public key associated with this object
        """
        return public_key(self.private_key)
