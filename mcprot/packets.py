# -*- coding: utf-8 -*-

"""
MIT License

Copyright (c) 2021 capslock321

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import struct
import asyncio
import gc
import logging
import zlib
import regex

from typing import Tuple, Union

from .auth import Authentication
from .exceptions import (
    OnlineServerException,
    InvalidConnectionDetails,
    AuthenticationRateLimit,
    OutdatedClientException,
)
from .utils.varint import write_varint, read_varint, read_data, decode_varint, pack_data

REGEX = regex.compile(
    r"\{(?:[^{}]|(?R))*\}"
)

class Packet:
    """The packet class, stores information about the packet.

    Attributes:
        length: The length of the packet.
        packet_id: The packet id of the packet.
        packet_data: The data recieved pertaining to this packet."""

    def __init__(self, length, packet_id, packet_data):
        self.length = length
        self.packet_id = packet_id
        self.packet_data = packet_data

    def __str__(self):
        return self.packet_data


class CompressedPacket(Packet):
    """Same as packet class, but includes the decompressed_size of the packet.
    If the decompressed_size is 0 then the packet is uncompressed.

    Attributes:
        decompressed_size: The size after decompression.
    """

    def __init__(self, *args, decompressed_size):
        super().__init__(*args)
        self.decompressed_size = decompressed_size

    def __str__(self):
        return self.packet_data


class PacketStream:
    def __init__(self, host, port, version: int = None, loop = asyncio.get_event_loop()):
        """The running packet stream, the connection the server.

        Attributes:
            host: The host to connect to.
            port: The port to connect to.
            loop: The event loop.
            handlers: The event handlers.
            encryptor: The packet encryptor.
            decryptor: The packet decryptor.
            threshold (int): The limit before mcprot have to be compressed.
            reader: The stream reader.
            writer: The stream writer.

        Raises:
            InvalidConnectionDetails: If the host or port is invalid.
        """
        self.host = host
        self.port = port
        self.version = version
        self.handlers = dict()
        self.encryptor = None
        self.decryptor = None
        self.threshold = -1
        self.loop = loop
        if isinstance(host, str) and isinstance(port, int):
            self.reader, self.writer = self.loop.run_until_complete(
                asyncio.open_connection(host, port)
            )
        else:
            raise InvalidConnectionDetails("The host or port is invalid!")

    def packet_handler(self, packet_id):
        """Decorator to add packet handler.
        Args:
            packet_id (int): The packet_id in which to handle."""

        def handler(function):
            self.handlers[packet_id] = function

        return handler

    def add_packet_handler(self, function, packet_id) -> bool:
        """Adds a packet handler.

        Args:
            function: The function in which to handle.
            packet_id: The packet_id of which to handle.

        Returns:
            bool: True if successful."""
        self.handlers[packet_id] = function
        return True

    @staticmethod
    def get_obj(function) -> Union[object, bool]:
        """Gets the class object where the function most likely came from.

        Args:
            function: The function of which to get the class of.

        Returns:
            obj: Class object if found.
            bool: False if a class object was not found."""
        cls_name = function.__qualname__.rsplit(".", 1)[0]
        for obj in gc.get_objects():
            if type(obj).__name__ == cls_name:
                return obj
        return False

    async def get_status(self) -> bytes:
        """Gets server info, such as version info.

        Returns:
            bytes: Server information."""
        payload = (b"\x00\x00", self.host, self.port, b"\x01")
        await self.send_packet(payload)
        await self.send_packet((b"\x00",))
        return await self.reader.read(1024)

    async def decompress_data(self) -> Tuple[bytes, int, int, int]:
        """Decompresses packet data if the packet data is compressed.

        Returns:
            packet_data: Packet bytes given by the server.
            packet_id: Packet ID given by the server.
            length: Length of packet.
            decompressed_size: Packet size after decompression. Can be 0."""
        length = await read_varint(self.reader, self.decryptor)
        packet_data = await read_data(self.reader, length, self.decryptor)
        decompressed_size = decode_varint(packet_data)
        try:
            offset = len(write_varint(decompressed_size))
        except TypeError:
            raise SystemExit("Exiting program, connection has been terminated.")
        if decompressed_size > 0:
            packet_data = zlib.decompress(packet_data[offset:])
            packet_id = decode_varint(packet_data)
            return packet_data, packet_id, length, decompressed_size
        else:
            packet_data = packet_data[offset:]
            packet_id = decode_varint(packet_data[1:])
            return packet_data, packet_id, length, decompressed_size

    async def decode_payload(self) -> Union[Packet, CompressedPacket]:
        """Decodes the payload to get it's length, and ID.
        If need be, it will decompress the packet.

        Returns:
            Packet: Packet information given by the server.
        """
        if self.threshold >= 0:
            (
                packet_data,
                packet_id,
                length,
                decompressed_size,
            ) = await self.decompress_data()
            return CompressedPacket(
                length, packet_id, packet_data, decompressed_size=decompressed_size
            )
        else:
            length = await read_varint(self.reader, self.decryptor)
            packet_data = await read_data(self.reader, length, self.decryptor)
            packet_id = decode_varint(packet_data)
            if packet_id == 3:
                threshold = decode_varint(packet_data[1:])
                self.threshold = threshold
                logging.info("Compression Enabled. Threshold: {}".format(threshold))
                return Packet(length, packet_id, threshold)
            else:
                return Packet(length, packet_id, packet_data)

    async def connect(
        self,
        username,
        access_token: str = None,
        uuid: str = None,
        handle_keep_alives: bool = True,
    ):
        """The connection to the server, will require a username, and a version (default: 754).
        If the server is an online server, an access_token and uuid is required.

        Args:
            username (str): The username in which to connect to the server under.
            version (int): The protocol version in which to use.
            access_token (str): (Optional) - The access token to connect to the server if the server is an online server.
            uuid (str): (Optional) - The uuid of the player to authenticate under.
            handle_keep_alives (bool): If you wish to handle the keep alives automatically.

        Raises:
            OnlineServerException: If the server is an online server, but no access_token and uuid was provided.
            AuthenticationRateLimit: If you are ratelimited from authenticating to Mojang.
        """
        if self.version is None:
            # Attempt to get protocol version.
            logging.info("A client version was not provided. Attempting to find server version.")
            self.version = self.get_status()
        client_version = write_varint(self.version)
        await self.send_packet((b"\x00", client_version, self.host, self.port, b"\x02"))
        logging.info(
            "Preforming handshake with version {} on {}:{}.".format(
                self.version, self.host, self.port
            )
        )
        await self.send_packet((b"\x00", username))
        logging.info("Starting login process with username {}.".format(username))
        packet = await self.decode_payload()
        if "Outdated client! Please use " in str(packet.packet_data):
            raise OutdatedClientException("Outdated Client! {}".format(packet.packet_data[2:]))
        if packet.packet_id == 1:
            logging.info("Server is an online server, attempting to login.")
            if access_token is None or uuid is None:
                logging.error(
                    "Server is an online server, but no access token or uuid was provided."
                )
                raise OnlineServerException(
                    "Server is an online server, but no access token or uuid was provided."
                )
            auth = Authentication(access_token, uuid)
            self.encryptor, self.decryptor = await auth.login(self, packet.packet_data)
        while packet.packet_id is not None:
            packet = await self.decode_payload()
            if isinstance(packet, CompressedPacket):
                logging.debug(
                    "Compressed packet received with ID {}.".format(packet.packet_id)
                )
            else:
                logging.debug(
                    "Uncompressed packet received with ID {}.".format(packet.packet_id)
                )
            if handle_keep_alives:
                if packet.packet_id == 33:
                    if self.threshold >= 0:
                        # We need to account for the Data Length parameter
                        # therefore we use [2:] and not [1:]
                        keep_alive_id = struct.unpack(">q", packet.packet_data[2:])[0]
                    else:
                        keep_alive_id = struct.unpack(
                            ">q",
                        )[0]
                    logging.debug(
                        "Sending keep alive with keep alive ID of {}.".format(
                            keep_alive_id
                        )
                    )
                    await self.send_packet((b"\x0f", struct.pack(">q", keep_alive_id)))
            if packet.packet_id == 0 and REGEX.findall(str(packet.packet_data)) is None:
                packet_data = packet.packet_data
                logging.error("Ratelimited while authenticating. Raising Exception.")
                raise AuthenticationRateLimit(
                    "Ratelimited while authenticating: {}".format(packet_data)
                )
            if packet.packet_id in self.handlers.keys():
                function = self.handlers[packet.packet_id]
                logging.info(
                    "Packet (ID: {}) with known handler found, executing {}."
                    "".format(packet.packet_id, function.__qualname__)
                )
                function_class = self.get_obj(function)
                if function_class is not False:
                    await function(function_class, packet)
                else:  # If the method is not in a class.
                    await function(packet)

    async def send_packet(self, payload):  # A bit redundant, maybe shorten it.
        """Sends a packet given a payload.

        Args:
            payload: A list of items to pack and send.
        """
        packets = list()
        for packet in payload:
            packets.append(pack_data(packet))
        payload = b"".join(packets)
        if self.threshold >= 0:
            if len(payload) >= self.threshold:
                compressed_data = zlib.compress(payload)
                # The plus one is there to account for the data length parameter. Don't forget it!
                payload = (
                    write_varint(len(compressed_data) + 1)
                    + len(payload)
                    + compressed_data
                )
                if self.encryptor is not None:
                    payload = self.encryptor.update(payload)
                logging.debug(
                    "Sending compressed packet with length of {}. Compression is enabled.".format(
                        len(payload)
                    )
                )
                return self.writer.write(payload)
            else:
                payload = write_varint(len(payload) + 1) + b"\x00" + payload
                if self.encryptor is not None:
                    payload = self.encryptor.update(payload)
                logging.debug(
                    "Sending uncompressed packet with length of {}. Compression is enabled.".format(
                        len(payload)
                    )
                )
                return self.writer.write(payload)
        else:
            payload = write_varint(len(payload)) + payload
            if self.encryptor is not None:
                payload = self.encryptor.update(payload)
            logging.debug(
                "Sending uncompressed packet with length of {}. Compression is not enabled.".format(
                    len(payload)
                )
            )
            return self.writer.write(payload)
