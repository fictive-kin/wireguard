
import os

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

from .utils import (
    value_list_to_comma,
    value_list_to_multiple,
)
from .constants import (
    CONFIG_PATH,
)


INTERFACE_KEYS = (
    'address',
    'dns',
    'port',
    'private_key',
    'pre_up',
    'post_up',
    'pre_down',
    'post_down',
    'save_config',
    'mtu',
    'table',
    'comments',  # We want this to be the last line/chunk in the output
)

PEER_KEYS = (
    'description',  # We want this to be the first key in the output
    'allowed_ips',
    'endpoint',
    'keepalive',
    'preshared_key',
    'public_key',
    'comments',  # We want this to be the last line/chunk in the output
)


class Config:  # pylint: disable=too-many-public-methods
    """
    The config for a WireGuard Peer
    """

    _peer = None

    def __init__(self, peer):
        # These 2 attributes are the bare minimum allowed to create a remote peer
        if not (hasattr(peer, 'allowed_ips') and
                hasattr(peer, 'public_key')):
            raise ValueError('You must provide a valid Peer, or subclass thereof')

        self._peer = peer

    @property
    def allowed_ips(self):
        """
        Returns the subnets that the remote peer should route to this peer
        """

        if not self._peer.allowed_ips:
            return None

        return value_list_to_comma('AllowedIPs', self._peer.allowed_ips)

    @property
    def dns(self):
        """
        Returns the DNS settings of the given peer for the config file
        """

        if not self._peer.dns:
            return None

        return value_list_to_comma('DNS', self._peer.dns)

    @property
    def pre_up(self):
        """
        Returns the PreUp settings of the given peer for the config file
        """

        if self._peer.pre_up is None:
            return None

        return value_list_to_multiple('PreUp', self._peer.pre_up)

    @property
    def pre_down(self):
        """
        Returns the PreDown settings of the given peer for the config file
        """

        if self._peer.pre_down is None:
            return None

        return value_list_to_multiple('PreDown', self._peer.pre_down)

    @property
    def post_up(self):
        """
        Returns the PostUp settings of the given peer for the config file
        """

        if self._peer.post_up is None:
            return None

        return value_list_to_multiple('PostUp', self._peer.post_up)

    @property
    def post_down(self):
        """
        Returns the PostDown settings of the given peer for the config file
        """

        if self._peer.post_down is None:
            return None

        return value_list_to_multiple('PostDown', self._peer.post_down)

    @property
    def preshared_key(self):
        """
        Returns the PresharedKey for this peer
        """

        if self._peer.preshared_key is None:
            return None

        return f'PresharedKey = {self._peer.preshared_key}'

    @property
    def private_key(self):
        """
        Returns the PrivateKey for this peer
        """
        return f'PrivateKey = {self._peer.private_key}'

    @property
    def public_key(self):
        """
        Returns the PublicKey for this peer
        """
        return f'PublicKey = {self._peer.public_key}'

    @property
    def save_config(self):
        """
        Returns the SaveConfig for this peer
        """

        if self._peer.save_config is None:
            return None

        value = 'true' if self._peer.save_config else 'false'
        return f'SaveConfig = {value}'

    @property
    def endpoint(self):
        """
        Returns the endpoint for this peer
        """

        if self._peer.endpoint is None:
            return None

        return f'Endpoint = {self._peer.endpoint}'

    @property
    def port(self):
        """
        Returns the Port for this peer
        """
        return f'ListenPort = {self._peer.port}'

    @property
    def keepalive(self):
        """
        Returns the PersistentKeepalive for this peer
        """

        if self._peer.keepalive is None:
            return None

        return f'PersistentKeepalive = {self._peer.keepalive}'

    @property
    def address(self):
        """
        Returns the Address for this peer
        """

        values = []
        for ip in self._peer.address:  # pylint: disable=invalid-name
            values.append(f'{ip}/{ip.max_prefixlen}')

        return value_list_to_comma('Address', values)

    @property
    def description(self):
        """
        Returns the name/description for this peer as a comment
        """

        if self._peer.description is None:
            return None

        return f'# {self._peer.description}'

    @property
    def comments(self):
        """
        Returns any comments that should be present in the generated file
        """

        if self._peer.comments is None:
            return None

        return value_list_to_multiple('#', self._peer.comments, key_value_separator=' ')

    @property
    def mtu(self):
        """
        Returns the mtu for this peer
        """

        if self._peer.mtu is None:
            return None

        return f'MTU = {self._peer.mtu}'

    @property
    def table(self):
        """
        Returns the table for this peer
        """

        if self._peer.table is None:
            return None

        return f'Table = {self._peer.table}'

    @property
    def interface(self):
        """
        Returns the Interface section of the config file
        """

        data = ['[Interface]']
        for item in INTERFACE_KEYS:
            value = getattr(self, item, None)
            if value:
                data.append(value)

        return os.linesep.join(data)

    @property
    def peers(self):
        """
        Returns the Peer sections for all connectable peers
        """

        # Guard against potentially having been instantiated with an invalid peer object
        if not isinstance(getattr(self._peer, 'peers', None), (list, set)):
            return ''

        peers_data = ''
        for peer in self._peer.peers:
            peers_data += peer.config.remote_config

            extras = []

            # Need to take special measures when the preshared keys aren't identical
            # And there is no need for an `else` clause, as the value would already have
            # been included by the `remote_config` returned data for normal cases
            if self.preshared_key != peer.config.preshared_key:

                # When only the remote peer has a key set, we need to use it too
                if self.preshared_key is None:
                    extras.append(peer.config.preshared_key)

                # When only this peer has a key set, the remote peer needs to use it too
                elif peer.config.preshared_key is None:
                    extras.append(self.preshared_key)

                # The keys have both been set, but are not a match.
                else:
                    raise ValueError(f'Preshared keys do not match for {self._peer} and {peer}')

            # Keepalive is always a local->remote keepalive, so we need to set the config
            # value based on our local value, rather than the remote's value.
            if self.keepalive:
                extras.append(self.keepalive)

            if extras:
                peers_data = os.linesep.join((peers_data, *extras, ""))
            else:
                peers_data = os.linesep.join((peers_data, ""))

        return peers_data

    @property
    def remote_config(self):
        """
        Returns the Peer section for use in a remote peer's config file
        """

        data = ['[Peer]']
        for item in PEER_KEYS:
            # Despite `PersistentKeepalive` being a peer option, it needs to be
            # set from the local side, not the remote side. Thus we cannot use
            # the remote peer's value of it or we'll be setup in reverse.
            if item == 'keepalive':
                continue

            value = getattr(self, item, None)
            if value:
                data.append(value)

        data = ('', *data)
        return os.linesep.join(data)

    @property
    def local_config(self):
        """
        Returns the full WireGuard config
        """
        return os.linesep.join((
            self.interface,
            '',
            self.peers,
        ))

    @property
    def qrcode(self):
        """
        Returns a QR Code of this peer's configuration
        """

        if not HAS_QRCODE:
            raise AttributeError('QR Code functionality is not enabled. Please add the qrcode '
                                 'library to this environment')

        return qrcode.make(self.local_config)

    @property
    def filename(self):
        """
        Returns the file name of the WireGuard config file
        """
        return f'{self._peer.interface}.conf'

    def full_path(self, config_path=None):
        """
        Returns the full path to the WireGuard config file
        """

        if config_path in [None, False]:
            config_path = CONFIG_PATH
        return os.path.join(config_path, self.filename)

    def write(self, config_path=None):
        """
        Writes the WireGuard config file
        """

        if config_path in [None, False]:
            config_path = CONFIG_PATH

        with open(self.full_path(config_path), mode='w', encoding='utf-8') as conf_fh:
            conf_fh.write(self.local_config)


class ServerConfig(Config):
    """
    A config specific to a WireGuard Server
    """

    @property
    def address(self):
        """
        Returns the Address for this Server
        """

        values = []
        if self._peer.ipv4:
            values.append(f'{self._peer.ipv4}/{self._peer.ipv4_subnet.prefixlen}')

        if self._peer.ipv6:
            values.append(f'{self._peer.ipv6}/{self._peer.ipv6_subnet.prefixlen}')

        return value_list_to_comma('Address', values)

    @property
    def peers_filename(self):
        """
        Returns the peers config file name
        """
        return f'{self._peer.interface}-peers.conf'

    def peers_full_path(self, config_path=None):
        """
        Returns the full path to the peers config file
        """
        if config_path in [None, False]:
            config_path = CONFIG_PATH
        return os.path.join(config_path, self.peers_filename)

    def write(self, config_path=None):
        """
        Write out the main config and the peers config files
        """

        if config_path in [None, False]:
            config_path = CONFIG_PATH
        peers_file = self.peers_full_path(config_path)

        with open(self.full_path(config_path), mode='w', encoding='utf-8') as conf_fh:
            conf_fh.write(self.interface + os.linesep)
            conf_fh.write(f'PostUp = wg addconf %i {peers_file}' + os.linesep)

        with open(peers_file, mode='w', encoding='utf-8') as peers_fh:
            peers_fh.write(self.peers + os.linesep)
