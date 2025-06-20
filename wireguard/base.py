import typing as t
import json

from subnet import (
    ip_address,
    ip_network,
    IPv4Address,
    IPv6Address,
)

from .constants import (
    INTERFACE,
    KEEPALIVE_MINIMUM,
    PORT,
)
from .utils import (
    generate_key,
    find_ip_and_subnet,
    public_key as nacl_public_key,
    IPAddressSet,
    IPNetworkSet,
)


class BasePeer:  # pylint: disable=too-many-instance-attributes
    """
    The Base Peer Class

    This is the main type of WireGuard object, representing both a server and a client
    """

    description: t.Union[str, None] = None
    _comments: t.Union[t.List[str], None] = None
    _endpoint: t.Union[str, None] = None
    _interface: t.Union[str, None] = None
    _ipv6_address: t.Union[IPv6Address, None] = None
    _ipv4_address: t.Union[IPv4Address, None] = None
    _port: t.Union[int, None] = None
    _private_key: t.Union[str, None] = None
    _public_key: t.Union[str, None] = None
    _keepalive: t.Union[int, None] = None
    allowed_ips: t.Union[IPNetworkSet, None] = None
    dns: t.Union[IPAddressSet, None] = None
    pre_up: t.Union[t.List[str], None] = None
    post_up: t.Union[t.List[str], None] = None
    pre_down: t.Union[t.List[str], None] = None
    post_down: t.Union[t.List[str], None] = None
    _mtu: t.Union[int, None] = None
    _table: t.Union[str, None] = None

    # pylint: disable=too-many-locals,too-many-branches,too-many-statements,too-many-arguments
    def __init__(
        self,
        description: str,
        *,
        comments: t.Union[str, None] = None,
        address: t.Union[str, list[str], None] = None,
        endpoint: t.Union[str, None] = None,
        port: t.Union[int, None] = None,
        private_key: t.Union[str, None] = None,
        public_key: t.Union[str, None] = None,
        preshared_key: t.Union[str, None] = None,
        keepalive: t.Union[int, None] = None,
        allowed_ips: t.Union[str, list[str], None] = None,
        dns: t.Union[str, list[str], None] = None,
        pre_up: t.Union[str, list[str], None] = None,
        post_up: t.Union[str, list[str], None] = None,
        pre_down: t.Union[str, list[str], None] = None,
        post_down: t.Union[str, list[str], None] = None,
        interface: t.Union[str, None] = None,
        mtu: t.Union[int, None] = None,
        table: t.Union[str, None] = None,
    ):

        self.allowed_ips = IPNetworkSet()
        self.dns = IPAddressSet()
        self.pre_up = []
        self.post_up = []
        self.pre_down = []
        self.post_down = []

        self.description = description
        self.comments = comments

        if not isinstance(
            address,
            (
                list,
                set,
                tuple,
            ),
        ):
            address = [address]

        if len(address) > 2:
            raise ValueError(
                "You cannot specify more than 2 IPs for this interface: 1 IPv4 + 1 IPv6"
            )

        # pylint: disable=invalid-name
        for value in address:
            ip, net = find_ip_and_subnet(value)  # pylint: disable=unused-variable
            if ip is None:
                raise ValueError(
                    f"'{value}' does not appear to be an IPv4 or IPv6 address"
                )

            if ip.version == 4:
                if self.ipv4:
                    raise ValueError("Cannot set a 2nd IPv4 address.")

                self.ipv4 = ip

            elif ip.version == 6:
                if self.ipv6:
                    raise ValueError("Cannot set a 2nd IPv6 address.")

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

    def __repr__(self) -> str:
        """
        A simplistic representation of this object
        """
        return (
            f"<{self.__class__.__name__} iface={self.interface} address={self.address}>"
        )

    def __iter__(
        self,
    ) -> t.Generator[
        t.Dict[
            str,
            t.Union[
                bool,
                int,
                str,
                t.List[str],
                IPAddressSet,
                IPNetworkSet,
                None,
            ],
        ],
        None,
        None,
    ]:
        """
        Iterates through this peer's attributes
        """

        yield from {
            "address": self.address.sorted(),
            "allowed_ips": self.allowed_ips.sorted(),
            "description": self.description,
            "dns": self.dns,
            "endpoint": self.endpoint,
            "interface": self.interface,
            "keepalive": self.keepalive,
            "mtu": self.mtu,
            "post_down": self.post_down,
            "post_up": self.post_up,
            "pre_down": self.pre_down,
            "pre_up": self.pre_up,
            "preshared_key": self.preshared_key,
            "private_key": self.private_key,
            "public_key": self.public_key,
            "table": self.table,
        }.items()

    def json(self, **kwargs) -> str:
        """
        Produces the JSON output for this object
        """

        from .utils import JSONEncoder  # pylint: disable=import-outside-toplevel

        if "cls" not in kwargs or not kwargs["cls"]:
            kwargs["cls"] = JSONEncoder

        return json.dumps(self, **kwargs)

    @property
    def comments(self) -> t.Union[t.List[str], None]:
        """
        Returns the comments list
        """

        return self._comments

    @comments.setter
    def comments(self, value: t.Union[str, t.List[str], None]) -> None:
        """
        Sets the comments list
        """

        if not isinstance(
            value,
            (
                list,
                set,
                tuple,
            ),
        ):
            value = [value]

        if self._comments is None:
            self._comments = []

        self._comments.extend(value)

    def add_comment(self, value: t.Union[str, t.List[str]]) -> None:
        """
        Adds a new comment(s) to the comments list
        """

        if not isinstance(
            value,
            (
                list,
                set,
                tuple,
            ),
        ):
            self.comments.append(value)
        else:
            self.comments.extend(value)

    @property
    def port(self) -> int:
        """
        Returns the port value
        """

        return self._port or PORT

    @port.setter
    def port(self, value: t.Union[int, None]) -> None:
        """
        Sets the port value
        """

        if value in [None, False]:
            value = PORT
        else:
            value = int(value)
        self._port = value

    @property
    def endpoint(self) -> t.Union[str, None]:
        """
        Returns the endpoint value
        """

        if not isinstance(self._endpoint, str):
            return None

        # This is the easiest sure way to know if the port is already part of the endpoint
        # and will work for domain names, IPv4 and IPv6 addresses
        if self._endpoint.endswith(f":{self.port}"):
            return self._endpoint

        return f"{self._endpoint}:{self.port}"

    @endpoint.setter
    def endpoint(self, value: t.Union[str, None]) -> None:
        """
        Sets the endpoint value
        """

        self._endpoint = value

    @property
    def interface(self) -> str:
        """
        Returns the interface value
        """

        return self._interface

    @interface.setter
    def interface(self, value: t.Union[str, None]) -> None:
        """
        Sets the interface value
        """

        if value in [None, False]:
            value = INTERFACE
        self._interface = value

    @property
    def ipv4(self) -> t.Union[IPv4Address, None]:
        """
        Returns the IPv4 address for this object
        """

        return self._ipv4_address

    @ipv4.setter
    def ipv4(self, value: t.Union[IPv4Address, None]) -> None:
        """
        Sets the IPv4 address for this connection
        """

        if value is None:
            self._ipv4_address = None
            return

        if not isinstance(value, IPv4Address):
            value = ip_address(value)

        if value.version != 4:
            raise ValueError("Cannot use IPv6 value to set IPv4")

        self._ipv4_address = value

    @property
    def ipv6(self) -> t.Union[IPv6Address, None]:
        """
        Returns the IPv4 address for this object
        """

        return self._ipv6_address

    @ipv6.setter
    def ipv6(self, value: t.Union[IPv6Address, None]) -> None:
        """
        Sets the IPv6 address for this connection
        """

        if value is None:
            self._ipv6_address = None
            return

        if not isinstance(value, IPv6Address):
            value = ip_address(value)

        if value.version != 6:
            raise ValueError("Cannot use IPv4 value to set IPv6")

        self._ipv6_address = value

    @property
    def address(self) -> IPAddressSet:
        """
        Returns the address(es) for this peer
        """

        ips = IPAddressSet()
        if self.ipv4 is not None:
            ips.add(self.ipv4)

        if self.ipv6 is not None:
            ips.add(self.ipv6)

        return ips

    @property
    def private_key(self) -> str:
        """
        Returns the WireGuard private key associated with this object
        """

        if self._private_key is not None:
            return self._private_key

        if self._public_key is not None and self._private_key is None:
            raise AttributeError(
                "Unable to retrieve private key. Public key is set,"
                " and the associated private key was not provided."
            )

        self._private_key = generate_key()
        return self._private_key

    @private_key.setter
    def private_key(self, value: str) -> None:
        if value is None:
            raise ValueError("Private key cannot be empty!")

        self._private_key = value

    @property
    def public_key(self) -> str:
        """
        Returns the WireGuard public key associated with this object
        """

        if self._public_key is not None:
            return self._public_key

        if self._private_key is not None:
            return nacl_public_key(self._private_key)

        raise AttributeError("Neither public key not private key are set!")

    @public_key.setter
    def public_key(self, value: t.Union[str, None]) -> None:
        """
        Sets the public key for when the private key is unavailable
        """

        if (
            self._private_key is not None
            and nacl_public_key(self._private_key) != value
        ):
            raise ValueError(
                "Cannot set public key to a value inconsistent with the private key!"
            )

        self._public_key = value

    @property
    def keepalive(self) -> t.Union[int, None]:
        """
        Returns the keepalive value
        """
        return self._keepalive

    @keepalive.setter
    def keepalive(self, value: t.Union[int, None]) -> None:
        """
        Sets the keepalive value
        """

        if value is not None:
            if not isinstance(value, int):
                raise ValueError("Keepalive value must be an integer")

            value = max(value, KEEPALIVE_MINIMUM)

        self._keepalive = value

    @property
    def mtu(self) -> t.Union[int, None]:
        """
        returns the mtu value
          WG Default = 1420 (dunno and leave it to automatic for best results)
          if you have to fix mtu depending on outer:
            ipv6 connections require 1280 as minimum (try 1300,1350,1400)
            PPPoE = try 1412 or lower
        """
        return self._mtu

    @mtu.setter
    def mtu(self, value: t.Union[int, None]) -> None:
        """
        Sets the mtu value
        """
        if value is not None:
            # Check for bool specifically, because bool is a subclass of int
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError("MTU value must be an integer")

            if value < 1280 or value > 1420:
                raise ValueError("MTU value must be in the range 1280-1420")

        self._mtu = value

    @property
    def table(self) -> t.Union[str, None]:
        """
        returns the routing table value
        """
        return self._table

    @table.setter
    def table(self, value: t.Union[str, None]) -> None:
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
                    raise TypeError("Table must not be a boolean")

                if not (0 < value < 253 or 255 < value < (2**31)):
                    raise ValueError("Table must be in the ranges 1-252, 256-(2°31-1)")

            except TypeError as exc:
                # special values allowed (auto=default, off=no route created)
                # ref: https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8
                if value not in ("auto", "off"):
                    raise ValueError(
                        'Table must be "auto", "off" or an integer value'
                    ) from exc

        self._table = value

    def add_nat_traversal(self, outbound_interface: str) -> None:
        """
        Adds appropriate PostUp/PostDown rules when this peer is acting as
        a NAT traversal interface
        """

        # pylint: disable=line-too-long
        post_up = [
            f"iptables -A FORWARD -i %i -o {outbound_interface} -j ACCEPT",
            f"iptables -A FORWARD -i {outbound_interface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            f"iptables -t nat -A POSTROUTING -o {outbound_interface} -j MASQUERADE",
        ]
        post_down = [
            f"iptables -D FORWARD -i %i -o {outbound_interface} -j ACCEPT",
            f"iptables -D FORWARD -i {outbound_interface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
            f"iptables -t nat -D POSTROUTING -o {outbound_interface} -j MASQUERADE",
        ]
        # pylint: enable=line-too-long

        self.post_up.extend(post_up)
        self.post_down.extend(post_down)
