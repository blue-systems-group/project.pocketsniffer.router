import sys

"""IP and port for listening client reply."""
LOCAL_IP = '192.168.1.1'
LOCAL_TCP_PORT = 6543
LOCAL_BACKLOG = 10

"""The port that pocketsniffer app listens on."""
CLIENT_TCP_PORT = 6543


"""Parameters for socket connection/read."""
BUF_SIZE = 64*1024
CONNECTION_TIMEOUT_SEC = 10
READ_TIMEOUT_SEC = 10

"""Port for listening controller collector requests."""
PUBLIC_TCP_PORT = 7654
PUBLIC_BACKLOG = 10

"""Port for client throughput test."""
HTTP_PORT = 8080


LOG_FILE = sys.stdout


"""Hardware specs."""
VALID_2GHZ_CHANNELS = range(1, 12)
VALID_5GHZ_CHANNELS = range(36, 49, 4) + range(149, 166, 4)
VALID_CHANNELS = VALID_2GHZ_CHANNELS + VALID_5GHZ_CHANNELS

VALID_2GHZ_TXPOWER_DBM = range(1, 31)
VALID_5GHZ_TXPOWER_DBM = range(1, 18)
VALID_TXPOWER_DBM = set(VALID_2GHZ_TXPOWER_DBM + VALID_5GHZ_TXPOWER_DBM)
