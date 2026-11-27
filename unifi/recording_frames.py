"""Join external detection reports to the primary stream’s recording clock."""

import asyncio
import hashlib
import struct
from collections import OrderedDict

FRAME_NOTICE = struct.Struct("!16s32sq")


def picture_key(payload):
    """Hash only H.264 picture NAL units from a length-prefixed access unit."""
    digest = hashlib.sha256()
    found = False
    while payload:
        if len(payload) < 4:
            return None
        size = int.from_bytes(payload[:4], "big")
        if not size or size > len(payload) - 4:
            return None
        unit, payload = payload[4:4 + size], payload[4 + size:]
        if unit[0] & 31 in (1, 5):
            unit = unit.rstrip(b"\0")
            digest.update(len(unit).to_bytes(4, "big"))
            digest.update(unit)
            found = True
    return digest.digest() if found else None


class RecordingFrames(asyncio.DatagramProtocol):
    def __init__(self):
        self.worker = None
        self.frames = OrderedDict()
        self.pending = {}

    def reset(self, worker=None):
        self.worker = worker
        self.frames.clear()
        for future in self.pending.values():
            if not future.done():
                future.set_result(None)
        self.pending.clear()

    def datagram_received(self, data, address):
        if len(data) != FRAME_NOTICE.size:
            return
        worker, key, stamp = FRAME_NOTICE.unpack(data)
        if worker != self.worker:
            return
        now = asyncio.get_running_loop().time()
        self.frames[key] = (stamp, now)
        self.frames.move_to_end(key)
        if len(self.frames) > 256:
            self.frames.popitem(last=False)
        future = self.pending.get(key)
        if future is not None and not future.done():
            future.set_result(stamp)

    async def resolve(self, key):
        loop = asyncio.get_running_loop()
        cached = self.frames.get(key)
        if cached and loop.time() - cached[1] <= 2:
            return cached[0]
        if self.worker is None or key in self.pending or len(self.pending) >= 32:
            return None
        future = self.pending[key] = loop.create_future()
        try:
            return await asyncio.wait_for(future, timeout=0.75)
        except TimeoutError:
            return None
        finally:
            if self.pending.get(key) is future:
                self.pending.pop(key)
