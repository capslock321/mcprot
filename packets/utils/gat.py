# -*- coding: utf-8 -*-

import aiohttp

from . import IncorrectCredentials

AUTH_TOKEN_URL = "https://login.live.com/oauth20_token.srf"

XBL_URL = "https://user.auth.xboxlive.com/user/authenticate"

XSTS_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"

MINECRAFT_URL = "https://api.minecraftservices.com/authentication/login_with_xbox"


async def get_access_token(
    client_id, client_secret, code, redirect_uri="https://localhost"
):
    """Given the client_id, client_secret, code and redirect_uri, get the XBL token.

    Args:
        client_id (str): The client_id from your azure application.
        client_secret (str): The client_secret form your azure application
        code: The code given by the first step.
        redirect_uri (str): The redirect uri you put in your application.

    Raises:
        IncorrectCredentials: If the client_id, client_secret, code or redirect_uri is incorrect.
    """
    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(AUTH_TOKEN_URL, data=payload) as response:
            response = await response.json()
            if response.get("access_token") is None:
                raise IncorrectCredentials(
                    "Incorrect client_id, secret or code provided."
                )
            return await get_xbl_token(response["access_token"])


async def get_xbl_token(access_token: str):
    """Gets the XBL token given an auth token.

    Args:
        access_token: Auth token from previous step.

    Raises:
        IncorrectCredentials: If the authentication token is incorrect.
    """
    payload = {
        "Properties": {
            "AuthMethod": "RPS",
            "SiteName": "user.auth.xboxlive.com",
            "RpsTicket": "d={}".format(access_token),
        },
        "RelyingParty": "http://auth.xboxlive.com",
        "TokenType": "JWT",
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(XBL_URL, json=payload) as response:
            response = await response.json()
            if response.get("Token") is None:
                raise IncorrectCredentials("Incorrect access_token was provided.")
            return await get_xsts_token(response["Token"])


async def get_xsts_token(token: str):
    """Gets the XSTS token and the user hash given the XBL token.

    Args:
        token: The XBL token to authenticate with.

    Raises:
        IncorrectCredentials: If the XBL token is incorrect.
    """
    payload = {
        "Properties": {"SandboxId": "RETAIL", "UserTokens": [token]},
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT",
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(XSTS_URL, json=payload) as response:
            response = await response.json()
            if response.get("Token") is None:
                raise IncorrectCredentials("Incorrect token was provided.")
            return await get_token(
                response["Token"], response["DisplayClaims"]["xui"][0]["uhs"]
            )


async def get_token(token: str, uhs: str) -> str:
    """Gets the access token given the XSTS token and the user hash.

    Args:
        token: The XSTS token from the previous step.
        uhs: The user hash from the previous step.

    Raises:
        IncorrectCredentials: If the token or uhs is incorrect.

    Returns:
        str: The access token to authenticate with Mojang.
    """
    payload = {"identityToken": "XBL3.0 x={};{}".format(uhs, token)}
    async with aiohttp.ClientSession() as session:
        async with session.post(MINECRAFT_URL, json=payload) as response:
            response = await response.json()
            if response.get("access_token") is None:
                raise IncorrectCredentials("Incorrect token or uhs was provided.")
            return response["access_token"]
