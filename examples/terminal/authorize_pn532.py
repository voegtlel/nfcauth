"""Optional PN532 launcher for the hardware-neutral authorization example."""

from __future__ import annotations

import asyncio

from authorize import authorize
from pn532_transport import Pn532Transport

if __name__ == "__main__":
    asyncio.run(authorize(Pn532Transport()))
