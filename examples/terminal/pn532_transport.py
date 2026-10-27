"""Optional PN532 transport example; it is not part of the core package."""

from __future__ import annotations

import asyncio


class Pn532Transport:
    def __init__(self) -> None:
        import board
        import busio
        from adafruit_pn532.i2c import PN532_I2C

        self._reader = PN532_I2C(busio.I2C(board.SCL, board.SDA), debug=False)
        self._reader.SAM_configuration()

    async def wait_for_device(self) -> None:
        while not await asyncio.to_thread(self._reader.read_passive_target, timeout=0.5):
            await asyncio.sleep(0.1)

    async def transceive(self, command: bytes, *, timeout_seconds: float = 2.0) -> bytes:
        async with asyncio.timeout(timeout_seconds):
            response = await asyncio.to_thread(
                self._reader.call_function,
                0x40,
                params=[0x01, *command],
                response_length=258,
            )
        if response is None or not response or response[0] != 0:
            raise RuntimeError("PN532 data exchange failed")
        return bytes(response[1:])

    async def close(self) -> None:
        await asyncio.to_thread(self._reader.reset)
