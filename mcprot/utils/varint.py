# -*- coding: utf-8 -*-

import struct

from typing import Union


async def read_varint(stream, decryptor=None) -> Union[bytes, bool]:
    """Reads the varint directly from the stream.
    If there is a decryptor, decrypt the packet first.

    Args:
        stream: The stream from where to read the bytes from.
        decryptor: The bytes decryptor if the packet is encrypted.

    Returns:
        bytes: packet_data if read was successful.
        bool: False if the read was not successful.
    """
    packet_data = 0
    total_bytes = 0
    while True:
        byte = await stream.read(1)
        # If it tries to add NoneType and int together,
        # it means that the connection has most likely been terminated.
        if decryptor is not None:
            byte = decryptor.update(byte)

        if len(byte) == 0:
            return packet_data

        byte = ord(byte)
        packet_data |= (byte & 0x7F) << 7 * total_bytes

        if not byte & 0x80:
            return packet_data

        total_bytes = total_bytes + 1

        if total_bytes > 5:
            return False


def pack_data(data) -> bytes:
    """Packs the data given for sending.

    Args:
        data: The data given.

    Returns:
        bytes: The packed byte data.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
        return write_varint(len(data)) + data
    elif isinstance(data, int):
        return struct.pack("H", data)
    elif isinstance(data, float):
        return struct.pack("Q", int(data))
    else:
        return data


async def read_data(stream, length, decryptor=None) -> bytes:
    """Reads from the packet stream.
    If the received data is not equal to the length, it will keep reading until it meets that length.

    Args:
        stream: The packet stream to read from.
        length: The amount of bytes to read.
        decryptor: If the packet is encrypted, decrypt the packet for reading.

    Returns:
        bytes: The packet data that was read.
    """
    packet_data = await stream.read(length)
    while len(packet_data) != length:
        packet_data += await stream.read(length - len(packet_data))
    if decryptor is not None:
        return decryptor.update(packet_data)
    return packet_data


def decode_varint(byte_data) -> bytes:
    """Decode varint given byte data.
    Unlike read_varint, this does not read from the stream.

    Args:
        byte_data: The byte data from which to decode from.

    Returns:
        bytes: The decoded packet_data.
    """
    packet_data = 0
    for iteration, byte in enumerate(byte_data):
        byte = struct.unpack(">B", byte.to_bytes(1, "big"))[0]
        packet_data |= (byte & 0x7F) << 7 * iteration
        if not byte & 0x80:
            return packet_data


def write_varint(data: int) -> bytes:
    """Given an integer, encode the integer into a varint.

    Args:
        data (int): The integer to encode into a varint.

    Returns:
        bytes: The encoded varint.
    """
    packed_packets = list()
    while data != 0:
        current_byte = data & 0x7F
        data >>= 7
        compiled_bytes = struct.pack("B", current_byte | (0x80 if data > 0 else 0))
        packed_packets.append(compiled_bytes)
    return b"".join(packed_packets)
