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

import logging
import aiohttp
import hashlib
import os

from typing import Tuple

from .utils.varint import decode_varint, write_varint
from .exceptions import IncorrectCredentials

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MINECRAFT_URL = "https://sessionserver.mojang.com/session/minecraft/join"  # The url required to authenticate.


class Authentication:

    """Authenticates with Mojang given an access token and uuid.
    If you do not have an access token, you can use /utils/gat.py to generate one.

    Attributes:
        access_token (str): The access token required to log in.
        uuid (str): The uuid of the player logging in.
        shared_secret: The generated shared_secret.
        key: The public_key when we get it.
    """

    def __init__(self, access_token: str, uuid: str):
        self.access_token = access_token
        self.uuid = uuid
        self.shared_secret = os.urandom(16)
        self.key = None

    def _decode_auth_data(self, packet_data: bytes) -> Tuple[bytes, bytes]:
        """Decode authentication data from the authentication packet.
        Retrives the public_key and the verify_token, both needed for authentication.
        Args:
            packet_data (bytes): The packet data that the server sent.
        Returns:
            bytes: public_key - The public_key the server sent.
            bytes: verify_token - The verify_token the server sent.
        """
        public_key_length = decode_varint(packet_data[2:])
        public_key = packet_data[4 : public_key_length + 4]
        verify_token = packet_data[public_key_length + 5 :]
        self.key = load_der_public_key(public_key, default_backend())
        return public_key, verify_token

    async def login(self, stream, packet_data: bytes):
        """Logs into the server using the given credentials.
        Retrives the public_key and the verify_token, both needed for authentication.
        Args:
            stream: The running stream.
            packet_data (bytes): The packet_data sent by the server.
        Returns:
            The encryptor and decryptor of the cipher generated.
        """
        public_key, verify_token = self._decode_auth_data(packet_data)
        encrypted_secret = self.key.encrypt(self.shared_secret, PKCS1v15())
        encrypted_verify_token = self.key.encrypt(verify_token, PKCS1v15())
        logging.info(
            "Generated shared secret. Shared Secret: {}".format(self.shared_secret)
        )
        verification_hash = self.make_digest((b"", self.shared_secret, public_key))
        payload = (
            b"\x01",
            write_varint(len(encrypted_secret)),
            encrypted_secret,
            write_varint(len(encrypted_verify_token)),
            encrypted_verify_token,
        )
        logging.info("Authenticating with Mojang with UUID {}.".format(self.uuid))
        await self.authenticate(self.access_token, self.uuid, verification_hash)
        # Making request to session server, this is what verifies us.
        cipher = self.create_cipher(self.shared_secret)
        await stream.send_packet(payload)
        logging.info("Authentication complete. Successfully logged in.")
        return cipher.encryptor(), cipher.decryptor()

    @staticmethod
    def create_cipher(shared_secret) -> Cipher:
        """Creates the cipher given a shared secret.
        Args:
            shared_secret (bytes): The generated shared_secret.
        Returns:
            Cipher: The cipher generated using the shared_secret.
        """
        AES = algorithms.AES(shared_secret)
        CFB8 = modes.CFB8(shared_secret)
        return Cipher(AES, CFB8, default_backend())

    @staticmethod
    async def authenticate(
        access_token: str, uuid: str, verification_hash: str
    ) -> bool:
        """Authenticates with Mojang.
        Args:
            access_token (str): The access_token which logs us in.
            uuid (str): The player's uuid.
            verification_hash (str): The generated hash.
        Returns:
            bool: True if the verification was successful.
        Raises:
            IncorrectCredentials: If the credentials given is incorrect.
        """
        uuid = uuid.replace("-", "")
        payload = {
            "accessToken": access_token,
            "selectedProfile": uuid,
            "serverId": verification_hash,
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(MINECRAFT_URL, json=payload) as response:
                if response.status == 204:
                    return True
                elif response.status >= 400:
                    logging.error(
                        "Access token or uuid is incorrect. Raising Exception."
                    )
                    raise IncorrectCredentials(
                        "The given access token or uuid is incorrect."
                    )

    @staticmethod
    def minecraft_digest(digest) -> str:
        """Method is a modified version of the make_digest method from barneygale/quarry.
        As of 9/4/21 11:41 EST, the method is in the folder quarry.net
        with the file name crypto.py. Perhaps I can write my own but too lazy.
        Args:
            digest: The given hash.
        Returns:
            str: The generated hexdigest."""
        digest = int(digest.hexdigest(), 16)
        if digest >> 39 * 4 & 0x8:
            digest = "-%x" % ((-digest) & (2 ** (40 * 4) - 1))
        else:
            digest = "%x" % digest
        return digest

    def make_digest(self, hash_data):
        """Generates a hash given data.
        Args:
            hash_data: The hash data given.
        Returns:
            The generated sha1 hash.
        """
        data = hashlib.sha1()
        for item in hash_data:
            data.update(item)
        return self.minecraft_digest(data)
