
from subnet import (
    ip_address,
    ip_network,
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
)


def find_ip_and_subnet(value):
    """
    Returns an IP and the subnet from a value

    If the value is an IP with no subnet information, the return is a tuple of ( IP, None )
    If the value is a subnet with no host bits set, the return is a tuple of ( None, subnet )

    Otherwise, the return is a tuple of ( IP, subnet )
    """

    if isinstance(value, (IPv4Network, IPv6Network)):
        return ( None, value )
    if isinstance(value, (IPv4Address, IPv6Address)):
        return ( value, None )

    # pylint: disable=invalid-name
    ip = None
    net = None

    try:
        if '/' not in value:
            return ( ip_address(value), None )

    except TypeError:
        return ( None, None )

    try:
        # If subnet includes host bits, then ip_network will fail, but we can probably
        # recover what the user actually wanted to do.
        net = ip_network(value)

    except ValueError as exc:
        if not isinstance(value, str) or '/' not in value:
            raise exc

        # The user is providing a subnet with host bits set, but `ip_address` does not
        # allow subnet to be included when parsing the address. Therefore, we chop it
        # out, leaving only the desired IP.
        ip = ip_address(value.split('/')[0])

        # We've got the desired address, now we can get the subnet appropriately.
        net = ip_network(value, strict=False)

    return ( ip, net )
