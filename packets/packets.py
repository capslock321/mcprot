import struct
import asyncio
import gc
import logging
import zlib
import regex

from .auth import Authentication
from .exceptions import OnlineServerException, InvalidConnectionDetails, AuthenticationRateLimit
from .utils.varint import write_varint, read_varint, read_data, decode_varint, pack_data

REGEX = regex.compile(r'\{(?:[^{}]|(?R))*\}')

"""
FILE STRUCTURE, TO BE CHANGED IF ISSUES ARISE
packets/
    __init__.py - self explanatory
    auth.py - we add auth shit
    packets.py - main stream runner
    exceptions.py - exceptions
    handlers.py - two methods, maybe idk
    utils/ 
        varint.py - varint shits
        gat.py - microsoft auth shit 

"""


class Packet:

    def __init__(self, length, packet_id, packet_data):
        self.length = length
        self.packet_id = packet_id
        self.packet_data = packet_data


class CompressedPacket(Packet):

    def __init__(self, *args, decompressed_size):
        super().__init__(*args)
        self.decompressed_size = decompressed_size


class PacketStream:

    def __init__(self, host, port):
        """
        NOW OBSOLETE!
        The packet states will be corresponded with an integer as given below.
        Note: Status is left out because it be useless for my application.
            Handshake: 0
            Login: 1
            Play: 2
        """
        self.host = host
        self.port = port
        self.loop = asyncio.get_event_loop()
        self.handlers = dict()
        self.encryptor = None
        self.decryptor = None
        self.threshold = -1
        if isinstance(host, str) and isinstance(port, int):
            self.reader, self.writer = self.loop.run_until_complete(asyncio.open_connection(host, port))
        else:
            raise InvalidConnectionDetails("The host or port is invalid!")

    def packet_handler(self, packet_id):
        def handler(function):
            self.handlers[packet_id] = function
        return handler

    def add_packet_handler(self, function, packet_id):
        self.handlers[packet_id] = function
        return True

    @staticmethod
    def get_inst(function):
        cls_name = function.__qualname__.rsplit('.', 1)[0]
        for obj in gc.get_objects():
            if type(obj).__name__ == cls_name:
                return obj
        return False

    async def get_status(self):
        payload = (b"\x00\x00", self.host, self.port, b"\x01")
        await self.send_packet(payload)
        await self.send_packet((b"\x00",))
        return await self.reader.read(1024)

    async def decompress_data(self):
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

    async def decode_payload(self):
        if self.threshold >= 0:
            packet_data, packet_id, length, decompressed_size = await self.decompress_data()
            return CompressedPacket(length, packet_id, packet_data, decompressed_size=decompressed_size)
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

    async def connect(self, username, version: int = 754,
                      access_token: str = None, uuid: str = None, handle_keep_alives: bool = True):
        client_version = write_varint(version)
        await self.send_packet((b"\x00", client_version, self.host, self.port, b"\x02"))
        logging.info("Preforming handshake with version {} on {}:{}.".format(version, self.host, self.port))
        await self.send_packet((b"\x00", username))
        logging.info("Starting login process with username {}.".format(username))
        packet = await self.decode_payload()
        if packet.packet_id == 1:
            logging.info("Server is an online server, attempting to login.")
            if access_token is None or uuid is None:
                logging.error("Server is an online server, but no access token or uuid was provided.")
                raise OnlineServerException("Server is an online server, but no access token or uuid was provided.")
            auth = Authentication(access_token, uuid)
            self.encryptor, self.decryptor = await auth.login(self, packet.packet_data)
        while packet.packet_id is not None:
            packet = await self.decode_payload()
            if isinstance(packet, CompressedPacket):
                logging.debug("Compressed packet received with ID {}.".format(packet.packet_id))
            else:
                logging.debug("Uncompressed packet received with ID {}.".format(packet.packet_id))
            if handle_keep_alives:
                if packet.packet_id == 33:
                    if self.threshold >= 0:
                        # We need to account for the Data Length parameter
                        # therefore we use [2:] and not [1:]
                        keep_alive_id = struct.unpack(">q", packet.packet_data[2:])[0]
                    else:
                        keep_alive_id = struct.unpack(">q", )[0]
                    logging.debug("Sending keep alive with keep alive ID of {}.".format(keep_alive_id))
                    await self.send_packet((b"\x0f", struct.pack(">q", keep_alive_id)))
            if packet.packet_id == 0 and REGEX.findall(str(packet.packet_data)) is None:
                packet_data = packet.packet_data
                logging.error("Ratelimited while authenticating. Raising Exception.")
                raise AuthenticationRateLimit("Ratelimited while authenticating: {}".format(packet_data))
            if packet.packet_id in self.handlers.keys():
                function = self.handlers[packet.packet_id]
                logging.info("Packet (ID: {}) with known handler found, executing {}."
                             "".format(packet.packet_id, function.__qualname__))
                function_class = self.get_inst(function)
                if function_class is not False:
                    await function(function_class, packet)
                else:  # If the method is not in a class.
                    await function(packet)

    async def send_packet(self, payload):
        packets = list()
        for packet in payload:
            packets.append(pack_data(packet))
        payload = b"".join(packets)
        if self.threshold >= 0:
            if len(payload) >= self.threshold:
                compressed_data = zlib.compress(payload)
                # The plus one is there to account for the data length parameter. Don't forget it!
                payload = write_varint(len(compressed_data) + 1) + len(payload) + compressed_data
                if self.encryptor is not None:
                    payload = self.encryptor.update(payload)
                logging.debug(
                    "Sending compressed packet with length of {}. Compression is enabled.".format(len(payload)))
                return self.writer.write(payload)
            else:
                payload = write_varint(len(payload) + 1) + b"\x00" + payload
                if self.encryptor is not None:
                    payload = self.encryptor.update(payload)
                logging.debug(
                    "Sending uncompressed packet with length of {}. Compression is enabled.".format(len(payload)))
                return self.writer.write(payload)
        else:
            payload = write_varint(len(payload)) + payload
            if self.encryptor is not None:
                payload = self.encryptor.update(payload)
            logging.debug(
                "Sending uncompressed packet with length of {}. Compression is not enabled.".format(len(payload)))
            return self.writer.write(payload)


if __name__ == '__main__':
    connection = PacketStream('localhost', 25565)
    loop = asyncio.get_event_loop()
    # Note: Token will expire every 24 hours from when it is generated.
    # print(loop.run_until_complete(connection.get_status()))
    loop.run_until_complete(
        connection.connect('capslock321', 756, open("token.txt").read(), "1d34cf0a36b64b178eba12d710dff822"))
    # 3:44PM 8-21-21 | Sync Code
