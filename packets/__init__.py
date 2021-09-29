"""Had some history with the project.
The history goes way back, back to early august of 2021
Just documenting shit now for future use.
Bumping to 1.2.0a to denote
1.0.0 = well the base, basic shit done - didnt document much shit with this time period.
1.0.1 = August 30 2021, fixed zlib compression
1.0.2 = Basic Encryption done
1.1.0 = Encryption completed on 9/4/21, wow that was a doozy. Easier than compression though, which is strange.
1.1.0a = 9/26/21 Updated and maybe final code
1.2.0a = 9/27/21 - Starting Revamp
"""

from .packets import PacketStream, Packet, CompressedPacket
from .exceptions import OnlineServerException, InvalidConnectionDetails, AuthenticationRateLimit
from .utils.varint import write_varint, read_varint, read_data, decode_varint

__version__ = '1.2.0a'

__author__ = 'capslock321'

__license__ = 'MIT'
