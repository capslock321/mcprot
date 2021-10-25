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


class PacketException(Exception):
    """The base of all exceptions that involve this module."""

    pass


class AuthenticationRateLimit(PacketException):
    """Raises when caused by authentication ratelimiting."""

    pass


class InvalidConnectionDetails(PacketException):
    """Raises when an invalid host or port is provided, as well as if we cannot connect to the server."""

    pass


class OnlineServerException(PacketException):
    """Raises if server is an online server, but you did not provide a uuid and access token."""

    pass


class IncorrectCredentials(PacketException):
    """Raises when the given information is incorrect."""

    pass

class OutdatedClientException(PacketException):
    """Raises if the client is outdated. You can get the server's version by using the get_status method."""
