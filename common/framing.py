"""
framing.py
----------
TCP is a STREAM of bytes, not a stream of messages.
If you call send("hi") then send("there"), the other side might
receive "hithere" in one recv(), or "hit" + "here" in two.

Fix: "length-prefixed framing".
Before every message we send its length as 4 bytes (big-endian),
then the message itself. The receiver:
    1. reads exactly 4 bytes  -> knows the length N
    2. reads exactly N bytes  -> gets one whole message

    +----------------+---------------------------+
    | length (4 B)   | message (length bytes)    |
    +----------------+---------------------------+
"""

import asyncio
import struct

# Largest frame we accept: 64 KB.
# Anything bigger is treated as an attack / bug and the connection is closed.
MAX_FRAME_SIZE = 64 * 1024

# ">I" = big-endian unsigned 32-bit integer (exactly 4 bytes)
LENGTH_FORMAT = ">I"
LENGTH_SIZE = struct.calcsize(LENGTH_FORMAT)  # = 4


class FrameError(Exception):
    """Raised when a frame is too large or the connection closes mid-frame."""


class FrameTooLarge(FrameError):
    """A frame bigger than MAX_FRAME_SIZE - logged as FRAME_TOO_LARGE."""


async def send_frame(writer: asyncio.StreamWriter, data: bytes) -> None:
    """Send one message (bytes) with a 4-byte length in front of it."""
    if len(data) > MAX_FRAME_SIZE:
        raise FrameError(f"Frame too large to send: {len(data)} bytes")

    # Pack the length into 4 bytes, then glue the data after it.
    header = struct.pack(LENGTH_FORMAT, len(data))
    writer.write(header + data)

    # drain() waits until the OS has accepted the bytes (flow control).
    await writer.drain()


async def recv_frame(reader: asyncio.StreamReader) -> bytes:
    """
    Receive exactly one message.
    Raises FrameError if the frame is too big or the peer disconnects.
    """
    try:
        # Step 1: read exactly 4 bytes for the length.
        header = await reader.readexactly(LENGTH_SIZE)
    except asyncio.IncompleteReadError:
        # The other side closed the connection.
        raise FrameError("Connection closed")

    (length,) = struct.unpack(LENGTH_FORMAT, header)

    # Step 2: refuse giant frames BEFORE reading them (protects memory).
    if length > MAX_FRAME_SIZE:
        raise FrameTooLarge(f"FRAME_TOO_LARGE: {length} bytes")

    try:
        # Step 3: read exactly `length` bytes.
        return await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        raise FrameError("Connection closed in the middle of a frame")
