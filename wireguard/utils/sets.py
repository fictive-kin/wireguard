
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

    def _coerce_value(self, value):  # pylint: disable=no-self-use
        raise NotImplementedError('ClassedSet must be not be used directly. Inherit from it, '
                                  'with appropriate value coersion logic implemented in the '
                                  'child class')

    def add(self, value):
        """
        Adds a value to this collection, maintaining uniqueness
        """

        if not value:
            raise ValueError(f'Cannot add an empty value to {self.__class__.__name__}')

        if isinstance(value, (list, set)):
            raise ValueError('Provided value must not be a list')

        super().add(self._coerce_value(value))

    def extend(self, values):
        """
        Adds multiple values to this collection, maintaining uniqueness
        """

        if not values:
            raise ValueError(f'Cannot add an empty value to {self.__class__.__name__}')

        if not isinstance(values, (list, set)):
            values = [values]

        for value in values:
            self.add(value)

class IPAddressSet(ClassedSet):
    """
    A set of IPv4Address/IPv6Address objects
    """

    def _coerce_value(self, value):  # pylint: disable=no-self-use
        """
        Coerce given values into an IP Address object
        """

        if not isinstance(value, (IPv4Address, IPv6Address)):
            value = ip_address(value)
        return value



class IPNetworkSet(ClassedSet):
    """
    A set of IPv4Network/IPv6Network objects
    """

    _ip_network_strict = True

    def _coerce_value(self, value):  # pylint: disable=no-self-use
        """
        Coerce given values into an IP Network object

        IP address objects/strings will automatically be set to `/32` or `/128` subnets
        by `ip_network()` when no netmask is specified. No special handling is required.
        """

        if not isinstance(value, (IPv4Network, IPv6Network)):
            value = ip_network(value, strict=self._ip_network_strict)
        return value


class NonStrictIPNetworkSet(IPNetworkSet):
    """
    A set of Non-Strict IPv4Network/IPv6Network objects

    Allows host bits to be set when corecing the value to an IPNetwork
    """

    _ip_network_strict = False
