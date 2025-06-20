CONFIG_PATH: str = "/etc/wireguard"
INTERFACE: str = "wg0"
PORT: int = 51820

# If you really need a keepalive value less than this, you might want to rethink your life
KEEPALIVE_MINIMUM: int = 5

MAX_ADDRESS_RETRIES: int = 100
MAX_PRIVKEY_RETRIES: int = (
    10  # If we can't get an used privkey in 10 tries, we're screwed
)
