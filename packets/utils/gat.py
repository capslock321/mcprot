import aiohttp
import asyncio

from packets.exceptions import IncorrectCredentials

AUTH_TOKEN_URL = "https://login.live.com/oauth20_token.srf"

XBL_URL = "https://user.auth.xboxlive.com/user/authenticate"

XSTS_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"

MINECRAFT_URL = "https://api.minecraftservices.com/authentication/login_with_xbox"


async def get_access_token(client_id, client_secret, code, redirect_uri="https://localhost"):
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(AUTH_TOKEN_URL, data=payload) as response:
            response = await response.json()
            if response.get("access_token") is None:
                raise IncorrectCredentials("Incorrect client_id, secret or code provided.")
            return await get_xbl_token(response['access_token'])


async def get_xbl_token(access_token: str):
    payload = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": "d={}".format(access_token)
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT"
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(XBL_URL, json=payload) as response:
            response = await response.json()
            if response.get("Token") is None:
                raise IncorrectCredentials("Incorrect access_token was provided.")
            return await get_xsts_token(response['Token'])


async def get_xsts_token(token: str):
    payload = {
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [
                token
            ]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(XSTS_URL, json=payload) as response:
            response = await response.json()
            if response.get("Token") is None:
                raise IncorrectCredentials("Incorrect token was provided.")
            return await get_token(response['Token'], response['DisplayClaims']['xui'][0]['uhs'])


async def get_token(token: str, uhs: str):
    payload = {
        "identityToken": "XBL3.0 x={};{}".format(uhs, token)
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(MINECRAFT_URL, json=payload) as response:
            response = await response.json()
            if response.get("access_token") is None:
                raise IncorrectCredentials("Incorrect token or uhs was provided.")
            return response['access_token']


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    print(loop.run_until_complete(
        get_access_token("7afcf80a-04c5-4c20-8be6-bc7f274e5615", "x9W7Q~EBQhhQsJp.to7ND4ActGJj4KXbEafua",
                                "M.R3_BL2.8fd36588-008a-7cb9-544c-1b23809d0d37")))
    # https://login.live.com/oauth20_authorize.srf?client_id=7afcf80a-04c5-4c20-8be6-bc7f274e5615&response_type=code%20&redirect_uri=https://localhost&scope=XboxLive.signin%20offline_access
