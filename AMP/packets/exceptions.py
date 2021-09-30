class PacketException(Exception):
    pass


class AuthenticationRateLimit(PacketException):
    pass


class InvalidConnectionDetails(PacketException):
    pass


class OnlineServerException(PacketException):
    pass


class IncorrectCredentials(PacketException):
    pass
