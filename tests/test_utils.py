
import pytest

from wireguard.utils import (
    ClassedSet,
    IPAddressSet,
    IPNetworkSet,
)


def test_classed_set_coerce_not_implemented():

    my_set = ClassedSet()

    with pytest.raises(NotImplementedError):
        my_set.add('something')

    assert not my_set


def test_classed_set_add_empty_value():

    my_set = ClassedSet()

    with pytest.raises(ValueError) as exc:
        my_set.add(None)
        assert 'empty value' in str(exc.value)

    with pytest.raises(ValueError) as exc:
        my_set.add(False)
        assert 'empty value' in str(exc.value)

    assert not my_set


def test_classed_set_add_list():
    my_set = ClassedSet()

    with pytest.raises(ValueError) as exc:
        my_set.add(['something'])
        assert 'not be a list' in str(exc.value)

    assert not my_set


def test_classed_set_extend_empty_value():

    my_set = ClassedSet()

    with pytest.raises(ValueError) as exc:
        my_set.extend(None)
        assert 'empty value' in str(exc.value)

    with pytest.raises(ValueError) as exc:
        my_set.extend([])
        assert 'empty value' in str(exc.value)

    assert not my_set


def test_classed_set_extend_non_list():

    my_set = IPAddressSet()  # Can't use ClassedSet directly due to coerce NotImplementedError
    my_set.extend('192.168.0.3')

    assert len(my_set) == 1


def test_ipaddress_set_not_ip_address():

    my_set = IPAddressSet()
    my_set.add('192.168.0.1')

    assert len(my_set) == 1


def test_ipnetwork_set_not_ip_network():

    my_set = IPNetworkSet()
    my_set.add('192.168.0.0/24')

    assert len(my_set) == 1
