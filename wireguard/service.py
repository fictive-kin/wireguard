
import platform
import subprocess

from datetime import datetime, timezone
from subnet import ip_interface

from .utils.sets import NonStrictIPNetworkSet


def _run(cmd):
    return subprocess.run(cmd, text=True, check=True, capture_output=True)


class InterfacePeer:
    interface = None
    peer = None

    ip_address = None
    preshared_key = None
    endpoint = None
    allowed_ips = []
    latest_handshake = None
    rx = 0
    tx = 0
    persistent_keepalive = False

    def __init__(self, interface, peer, **data):
        if not interface:
            raise ValueError('Interface must be supplied')
        if not peer:
            raise ValueError('Peer must be supplied')

        self.interface = interface
        self.peer = peer

        if data:
            self.load(data)

    def __repr__(self):
        return f'<InterfacePeer iface={self.interface} peer={self.peer} tx={self.tx} rx={self.rx}>'

    @property
    def is_connected(self):
        if self.ip_address:
            try:
                return ping(str(self.ip_address))
            except subprocess.CalledProcessError:
                pass
        return False

    def load(self, data):
        if not isinstance(data, dict):
            raise ValueError('Invalid value for data. It must be a dict')

        for key, value in data.items():
            if key in ['interface', 'peer', 'load'] or key.startswith('_'):
                continue

            if key == 'latest_handshake':
                if not isinstance(value, datetime):
                    value = datetime.fromtimestamp(int(value)).replace(tzinfo=timezone.utc)

            elif key == 'allowed_ips':
                if value is None:
                    continue
                elif not isinstance(value, (list, set)):
                    subnets = value.split(',')
                else:
                    subnets = value

                value = NonStrictIPNetworkSet()
                value.extend(subnets)

                if 'ip_address' not in data and len(subnets) == 1:
                    self.ip_address = ip_interface(subnets[0]).ip

            setattr(self, key, value)


class Interface:

    interface = None

    def __init__(self, interface):
        if not interface:
            raise ValueError('Interface must be supplied')

        self.interface = interface

    def __repr__(self):
        return f'<Interface iface={self.interface}>'

    def show(self, extra=None):
        cmd = [
            'wg',
            'show',
            self.interface,
        ]

        if extra:
            if not isinstance(extra, (list, set)):
                cmd.append(extra)
            else:
                cmd.extend(extra)

        return _run(cmd)

    def stop(self):
        return _run([
            'wg-quick',
            'down',
            self.interface,
        ])

    def restart(self):
        self.stop()
        return self.start()

    def start(self):
        return _run([
            'wg-quick',
            'up',
            self.interface,
        ])

    def sync(self, config_file):
        return _run([
            'wg',
            'syncconf',
            self.interface,
            config_file,
        ])

    def add(self, config_file):
        return _run([
            'wg',
            'addconf',
            self.interface,
            config_file,
        ])

    def peer(self, peer):
        return InterfacePeer(self.interface, peer)

    def public_key(self):
        return self.show('public-key').stdout.replace('\n', '')

    def dump(self):
        return self.show('dump')

    def stats(self):
        public_key = self.public_key()
        output = self.dump()
        peers = {}
        for line in output.stdout.split('\n'):
            if public_key in line:
                continue
            peerstat = line.split()
            try:
                peer = self.peer(peerstat[0])
                data = {
                    'preshared_key': peerstat[1] if peerstat[1] != '(none)' else None,
                    'endpoint':  peerstat[2] if peerstat[2] != '(none)' else None,
                    'allowed_ips': peerstat[3] if peerstat[3] != '(none)' else None,
                    'latest_handshake': peerstat[4] if peerstat[4] else None,
                    'rx': peerstat[5],
                    'tx': peerstat[6],
                    'persistent_keepalive': peerstat[7] if peerstat[7] != 'off' else False,
                }
            except IndexError:
                print(line)

            peer.load(data)
            peers.update({peer.peer: peer})

        return peers

    def peers(self):
        output = self.show('peers')
        peers = []
        for line in output.stdout.split('\n'):
            peers.append(self.peer(line))

        return peers


def ping(host):
    """
    Ref: https://stackoverflow.com/questions/2953462/pinging-servers-in-python/32684938#32684938

    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """

    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower() == 'windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', '-W', '1', host]

    return _run(command)
