import typing as t

from subnet import ip_address

from .base import BasePeer
from .config import Config
from .service import Interface
from .utils import (
    ClassedSet,
    IPAddressSet,
    IPNetworkSet,
)


class PeerSet(ClassedSet):
    """
    A set of Peer objects
    """

    def _coerce_value(self, value: t.Union[BasePeer, t.Dict[str, t.Any]]) -> BasePeer:
        """
        Bomb if a Peer object is not provided or cannot be coerced from a dict
        """

        if isinstance(value, BasePeer):
            return value

        if isinstance(value, dict):
            try:
                return BasePeer(**value)
            except ValueError as exc:
                raise ValueError("Provided value must be an instance of Peer") from exc

        raise ValueError("Provided value must be an instance of Peer")

    def discard_by_description(self, description: str) -> None:
        """
        Discard a peer by description
        """

        try:
            self.remove_by_description(description)
        except KeyError:
            pass

    def remove_by_description(self, description: str) -> None:
        """
        Remove a peer by description
        """

        for peer in self:
            if peer.description == description:
                self.remove(peer)
                return

        raise KeyError(description)

    def discard_by_ip(self, ip: str) -> None:
        """
        Discard a peer by ip
        """

        try:
            self.remove_by_ip(ip)
        except KeyError:
            pass

    def remove_by_ip(self, ip: str) -> None:
        """
        Remove a peer by ip
        """

        chk_ip = ip_address(ip)
        for peer in self:
            if chk_ip in [peer.ipv6, peer.ipv4]:
                self.remove(peer)
                return

        raise KeyError(ip)

    def discard_by_private_key(self, key: str) -> None:
        """
        Discard a peer by private key
        """

        try:
            self.remove_by_private_key(key)
        except KeyError:
            pass

    def remove_by_private_key(self, key: str) -> None:
        """
        Remove a peer by private key
        """

        for peer in self:
            if peer.private_key and peer.private_key == key:
                self.remove(peer)
                return

        raise KeyError(key)

    def discard_by_public_key(self, key: str) -> None:
        """
        Discard a peer by public key
        """

        try:
            self.remove_by_public_key(key)
        except KeyError:
            pass

    def remove_by_public_key(self, key: str) -> None:
        """
        Remove a peer by public key
        """

        for peer in self:
            if peer.public_key == key:
                self.remove(peer)
                return

        raise KeyError(key)


class Peer(BasePeer):  # pylint: disable=too-many-instance-attributes
    """
    The Peer Class

    This is the main type of WireGuard object, representing both a server and a client
    """

    peers: t.Union[PeerSet, None] = None
    save_config: t.Union[bool, None] = None

    _config: t.Union[dict, None] = None
    _service: t.Union[str, None] = None

    _config_cls: t.Union[Config, None] = None
    _service_cls: t.Union[Interface, None] = None

    # pylint: disable=too-many-locals,too-many-branches,too-many-statements,too-many-arguments
    def __init__(
        self,
        description: str,
        *,
        peers: t.Union[t.List[BasePeer], PeerSet, t.List[t.Dict[str, t.Any]], None] = None,
        save_config: t.Union[bool, None] = None,
        config_cls: t.Union[Config, None] = None,
        service_cls: t.Union[Interface, None] = None,
        **kwargs,
    ):

        super().__init__(description, **kwargs)

        self.peers = PeerSet()

        if save_config is not None:
            self.save_config = save_config

        self.config_cls = config_cls
        self.service_cls = service_cls

        if peers:
            if isinstance(peers, (list, set, tuple)):
                self.peers.extend(peers)
            else:
                self.peers.add(peers)

    def __iter__(
        self,
    ) -> t.Generator[
        dict[
            str,
            t.Union[
                bool,
                int,
                str,
                t.List[str],
                t.List[t.Dict[str, t.Any]],
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

        Note: the `peers` attribute is handled specially to prevent circular references
              when using `json.dumps()` of Peer objects. Should you desire to dump more
              attributes from each peer, you will need to do so manually.
        """

        peers = []
        for peer in self.peers:
            peers.append(
                {
                    "address": peer.address.sorted(),
                    "description": peer.description,
                    "public_key": peer.public_key,
                }
            )
        peers.sort(key=lambda x: x["description"])

        yield from {
            "save_config": self.save_config,
            "peers": peers,
        }.items()
        yield from super().__iter__()

    def remove_peer(self, peer: BasePeer, *, bidirectional: bool = True) -> None:
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
    def config_cls(self) -> Config:
        """
        Returns the config_cls value
        """

        if not self._config_cls:
            self._config_cls = Config

        return self._config_cls

    @config_cls.setter
    def config_cls(self, value: t.Union[Config, None]) -> None:
        """
        Sets the config_cls value
        """

        if value is not None and not issubclass(value, Config):
            raise ValueError("Provided value must be a subclass of Config")

        self._config_cls = value

    @property
    def service_cls(self) -> Interface:
        """
        Returns the service_cls value
        """

        if not self._service_cls:
            self._service_cls = Interface

        return self._service_cls

    @service_cls.setter
    def service_cls(self, value: t.Union[Interface, None]) -> None:
        """
        Sets the service_cls value
        """

        if value is not None and not issubclass(value, Interface):
            raise ValueError("Provided value must be a subclass of Interface")

        self._service_cls = value

    @property
    def config(self) -> Config:
        """
        Return the wireguard config file for this peer
        """

        if not isinstance(self._config, self.config_cls.__class__):
            self._config = self.config_cls(self)

        return self._config

    @property
    def service(self) -> Interface:
        """
        Returns the service interface for this peer
        """

        if not isinstance(self._service, self.service_cls.__class__):
            self._service = self.service_cls(self.interface)

        return self._service
