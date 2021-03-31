
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


INTERFACE_KEYS = [
    'address',
    'dns',
    'port',
    'private_key',
    'pre_up',
    'post_up',
    'pre_down',
    'post_down',
    'save_config',
]

PEER_KEYS = [
    'allowed_ips',
    'description',
    'endpoint',
    'keepalive',
    'preshared_key',
    'public_key',
]


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

        return value_list_to_comma('AllowedIPs', self._peer.allowed_ips)

    @property
    def dns(self):
        """
        Returns the DNS settings of the given peer for the config file
        """

        return value_list_to_comma('DNS', self._peer.dns)

    @property
    def pre_up(self):
        """
        Returns the PreUp settings of the given peer for the config file
        """

        return value_list_to_multiple('PreUp', self._peer.pre_up)

    @property
    def pre_down(self):
        """
        Returns the PreDown settings of the given peer for the config file
        """

        return value_list_to_multiple('PreDown', self._peer.pre_down)

    @property
    def post_up(self):
        """
        Returns the PostUp settings of the given peer for the config file
        """

        return value_list_to_multiple('PostUp', self._peer.post_up)

    @property
    def post_down(self):
        """
        Returns the PostDown settings of the given peer for the config file
        """

        return value_list_to_multiple('PostDown', self._peer.post_down)

    @property
    def preshared_key(self):
        """
        Returns the PresharedKey for this peer
        """
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
        value = 'true' if self._peer.save_config else 'false'
        return f'SaveConfig = {value}'

    @property
    def endpoint(self):
        """
        Returns the endpoint for this peer
        """
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
        return f'PersistentKeepalive = {self._peer.keepalive}'

    @property
    def address(self):
        """
        Returns the Address for this peer
        """
        return f'Address = {self._peer.address}/{self._peer.address.max_prefixlen}'

    @property
    def description(self):
        """
        Returns the name/description for this peer as a comment
        """
        return f'# {self._peer.description}'

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

        return '''
'''.join(data)

    @property
    def peers(self):
        """
        Returns the Peer sections for all connectable peers
        """

        peers_data = ''
        for peer in getattr(self._peer, 'peers', []):
            peers_data += peer.config().remote_config
        return peers_data

    @property
    def remote_config(self):
        """
        Returns the Peer section for use in a remote peer's config file
        """

        data = ['[Peer]']
        for item in PEER_KEYS:
            value = getattr(self, item, None)
            if value:
                data.append(value)

        return '''
'''.join(data)

    @property
    def local_config(self):
        """
        Returns the full WireGuard config
        """
        return f'''
{self.interface}

{self.peers}
'''

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

    def full_path(self, config_path=CONFIG_PATH):
        """
        Returns the full path to the WireGuard config file
        """
        return os.path.join(config_path, self.filename)

    def write(self, config_path=CONFIG_PATH):
        """
        Writes the WireGuard config file
        """

        with open(self.full_path(config_path), 'w') as conf_fh:
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
        return f'Address = {self._peer.address}/{self._peer.subnet.prefixlen}'

    @property
    def peers_filename(self):
        """
        Returns the peers config file name
        """
        return f'{self._peer.interface}-peers.conf'

    def peers_full_path(self, config_path=CONFIG_PATH):
        """
        Returns the full path to the peers config file
        """
        return os.path.join(config_path, self.peers_filename)

    def write(self, config_path=CONFIG_PATH):
        """
        Write out the main config and the peers config files
        """

        peers_file = self.peers_full_path(config_path)

        with open(self.full_path(config_path), 'w') as conf_fh:
            conf_fh.write(self.interface)
            conf_fh.write(f'PostUp = wg addconf %i {peers_file}')

        with open(peers_file, 'w') as peers_fh:
            peers_fh.write(self.peers)
