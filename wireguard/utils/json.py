
import json

from subnet import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
)

from .sets import ClassedSet


class JSONEncoder(json.JSONEncoder):
    """
    A custom JSON encoder that handles the types we use within this module
    """

    def default(self, o):
        if isinstance(o, (IPv4Address, IPv6Address, IPv4Network, IPv6Network,)):
            return str(o)

        if isinstance(o, ClassedSet):
            return list(o)

        from ..peer import Peer  # pylint: disable=import-outside-toplevel,cyclic-import
        if isinstance(o, Peer):
            return dict(o)

        return super().default(o)
