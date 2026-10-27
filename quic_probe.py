"""QUIC/HTTP3 handshake probe.

Usage: quic_probe.py HOST PORT SNI
Prints "ok <ms>" on completed QUIC handshake, exits non-zero otherwise.
Certificate verification is disabled on purpose: the endpoint serves a
certificate issued for its real name while the probe uses a masquerade SNI;
handshake completion is the availability signal.
"""

import asyncio
import ssl
import sys
import time

from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration

TIMEOUT_S = 10.0


async def main(host: str, port: int, sni: str) -> int:
    config = QuicConfiguration(
        is_client=True,
        alpn_protocols=["h3"],
        verify_mode=ssl.CERT_NONE,
        server_name=sni,
    )
    started = time.monotonic()
    async with connect(host, port, configuration=config, wait_connected=True):
        print(f"ok {int((time.monotonic() - started) * 1000)}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: quic_probe.py HOST PORT SNI", file=sys.stderr)
        sys.exit(2)
    try:
        sys.exit(
            asyncio.run(
                asyncio.wait_for(
                    main(sys.argv[1], int(sys.argv[2]), sys.argv[3]),
                    TIMEOUT_S,
                )
            )
        )
    except Exception as exc:  # noqa: BLE001 - probe must never traceback
        print(f"fail: {exc}", file=sys.stderr)
        sys.exit(1)
