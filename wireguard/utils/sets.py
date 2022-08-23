
from subnet import (
    ip_address,
    ip_network,
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
)


class ClassedSet(set):
    """
    A set that requires members be of a specific class
    """

    def _coerce_value(self, value):
        raise NotImplementedError('ClassedSet must be not be used directly. Inherit from it, '
                                  'with appropriate value coersion logic implemented in the '
                                  'child class')

    def add(self, value):
        """
        Adds a value to this collection, maintaining uniqueness
        """

        if not value:
            raise ValueError(f'Cannot add an empty value to {self.__class__.__name__}')

        if isinstance(value, (list, set, tuple,)):
            raise ValueError('Provided value must not be a list')

        super().add(self._coerce_value(value))

    def extend(self, values):
        """
        Adds multiple values to this collection, maintaining uniqueness
        """

        if not values:
            raise ValueError(f'Cannot add an empty value to {self.__class__.__name__}')

        if not isinstance(values, (list, set, tuple,)):
            values = [values]

        for value in values:
            self.add(value)


class IPAddressSet(ClassedSet):
    """
    A set of IPv4Address/IPv6Address objects
    """

    def _coerce_value(self, value):
        """
        Coerce given values into an IP Address object
        """

        # Check for booleans specifically, as those are technically ints, and will not
        # cause `ip_address()` to raise an error
        if isinstance(value, bool):
            raise ValueError(
                f'Could not convert to IP Address: {type(value)}({value})')

        if not isinstance(value, (IPv4Address, IPv6Address)):
            try:
                value = ip_address(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f'Could not convert to IP Address: {type(value)}({value})') from exc

        return value

    def __str__(self):
        string_values = []
        for ip in self:  # pylint: disable=invalid-name
            string_values.append(f'{ip.address}/{ip.max_prefixlen}')
        return ','.join(string_values)

class IPNetworkSet(ClassedSet):
    """
    A set of IPv4Network/IPv6Network objects
    """

    _ip_network_strict = True

    def _coerce_value(self, value):
        """
        Coerce given values into an IP Network object

        IP address objects/strings will automatically be set to `/32` or `/128` subnets
        by `ip_network()` when no netmask is specified. No special handling is required.
        """

        # Check for booleans specifically, as those are technically ints, and will not
        # cause `ip_network()` to raise an error
        if isinstance(value, bool):
            raise ValueError(
                f'Could not convert to IP Network: {type(value)}({value})')

        if not isinstance(value, (IPv4Network, IPv6Network)):
            try:
                value = ip_network(value, strict=self._ip_network_strict)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f'Could not convert to IP Network: {type(value)}({value})') from exc

        return value

    def __str__(self):
        string_values = []
        for net in self:
            string_values.append(f'{str(net.network_address)}/{net.prefixlen}')
        return ','.join(string_values)


class NonStrictIPNetworkSet(IPNetworkSet):
    """
    A set of Non-Strict IPv4Network/IPv6Network objects

    Allows host bits to be set when corecing the value to an IPNetwork
    """

    _ip_network_strict = False
