import logging
import aiohttp
import hashlib
import os

from .utils.varint import decode_varint, write_varint
from .exceptions import IncorrectCredentials

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MINECRAFT_URL = "https://sessionserver.mojang.com/session/minecraft/join"


class Authentication:

    def __init__(self, access_token: str, uuid: str):
        self.access_token = access_token
        self.uuid = uuid
        self.shared_secret = os.urandom(16)
        self.key = None

    def _decode_auth_data(self, packet_data):
        public_key_length = decode_varint(packet_data[2:])
        public_key = packet_data[4:public_key_length + 4]
        verify_token = packet_data[public_key_length + 5:]
        self.key = load_der_public_key(public_key, default_backend())
        return public_key, verify_token

    async def login(self, stream, packet_data):
        public_key, verify_token = self._decode_auth_data(packet_data)
        encrypted_secret = self.key.encrypt(self.shared_secret, PKCS1v15())
        encrypted_verify_token = self.key.encrypt(verify_token, PKCS1v15())
        logging.info("Generated shared secret. Shared Secret: {}".format(self.shared_secret))
        verification_hash = self.make_digest((b"", self.shared_secret, public_key))
        payload = (b"\x01", write_varint(len(encrypted_secret)), encrypted_secret,
                   write_varint(len(encrypted_verify_token)), encrypted_verify_token)
        logging.info("Authenticating with Mojang with UUID {}.".format(self.uuid))
        await self.authenticate(self.access_token, self.uuid, verification_hash)
        # Making request to session server, this is what verifies us.
        cipher = self.create_cipher(self.shared_secret)
        await stream.send_packet(payload)
        logging.info("Authentication complete. Successfully logged in.")
        return cipher.encryptor(), cipher.decryptor()

    @staticmethod
    def create_cipher(shared_secret):
        AES = algorithms.AES(shared_secret)
        CFB8 = modes.CFB8(shared_secret)
        return Cipher(AES, CFB8, default_backend())

    @staticmethod
    async def authenticate(access_token: str, uuid: str, verification_hash: str):
        uuid = uuid.replace("-", "")
        payload = {
            "accessToken": access_token,
            "selectedProfile": uuid,
            "serverId": verification_hash
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(MINECRAFT_URL, json=payload) as response:
                if response.status == 204:
                    return True
                elif response.status >= 400:
                    logging.error("Access token or uuid is incorrect. Raising Exception.")
                    raise IncorrectCredentials("The given access token or uuid is incorrect.")

    @staticmethod
    def minecraft_digest(digest):
        # Method is a modified version of the make_digest method from barneygale/quarry.
        # As of 9/4/21 11:41 EST, the method is in the folder quarry.net
        # with the file name crypto.py. Perhaps I can write my own but too lazy.
        digest = int(digest.hexdigest(), 16)
        if digest >> 39 * 4 & 0x8:
            digest = "-%x" % ((-digest) & (2 ** (40 * 4) - 1))
        else:
            digest = "%x" % digest
        return digest

    def make_digest(self, hash_data):
        data = hashlib.sha1()
        for item in hash_data:
            data.update(item)
        return self.minecraft_digest(data)
