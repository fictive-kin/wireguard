import os

def value_list_to_comma(ini_key, values):
    """
    Returns a comma separated list for use as a value in a WireGuard config file
    """

    if isinstance(values, (list, set, tuple,)):
        # Need to force to string, because the values are probably not simple strings
        values = ','.join(str(val) for val in values)

    return f'{ini_key} = {values}'


def value_list_to_multiple(ini_key, values, key_value_separator=' = '):
    """
    Returns multiple config lines for a given list of values
    """

    if not isinstance(values, (list, set, tuple,)):
        values = [values]

    data = []
    for value in values:
        data.append(f'{ini_key}{key_value_separator}{value}')

    return os.linesep.join(data)
