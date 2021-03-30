
CONFIG_PATH = '/etc/wireguard'
INTERFACE = 'wg0'
PORT = 51820

# If you really need a keepalive value less than this, you might want to rethink your life
KEEPALIVE_MINIMUM = 5

MAX_ADDRESS_RETRIES = 100
MAX_PRIVKEY_RETRIES = 10  # If we can't get an used privkey in 10 tries, we're screwed
