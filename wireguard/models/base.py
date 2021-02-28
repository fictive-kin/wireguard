

from subnet import ip_network, ip_address

from ..utils import generate_key, public_key


CONFIG_PATH = '/etc/wireguard'
INTERFACE = 'wg0'
PORT = 51820


class WireGuardBase:

    name = None
    subnet = None
    _address = None
    port = None
    _private_key = None
    config_path = None
    interface = None
    server = None

    def __init__(self,
                 name,
                 subnet,
                 address=None,
                 port=None,
                 private_key=None,
                 config_path=None,
                 interface=None,
                 server=None,
        ):

        self.name = name
        self.subnet = ip_network(subnet)

        if address is None:
            self._address = self.subnet.random_ip()

        else:
            self.address = address

        self._private_key = private_key

        self.port = int(port) if port is not None else PORT
        self.config_path = config_path if config_path is not None else CONFIG_PATH
        self.interface = interface if interface is not None else INTERFACE

        self.server = server


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
        Returns the WireGuard private key associated with this client
        """

        if self._private_key is not None:
            return self._private_key

        self._private_key = generate_key()
        if not self.server:
            return self._private_key

        count = 0
        while count < MAXIMUM_KEY_RETRIES:
            self._private_key = generate_key()
            if self._private_key not in self.server.client_keys:
                break
            count += 1

        if count >= MAXIMUM_KEY_RETRIES:
            raise WireguardKeyGenerationError()

        return self._private_key

    @property
    def public_key(self):
        """
        Returns the WireGuard public key associated with this gateway
        """
        return public_key(self.private_key)
