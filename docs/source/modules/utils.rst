Utilities
===============================
The following are utility functions, mostly concerning access token retrieval and varint processing.

Microsoft Authentication
-------------------------------
This module seeks to make authenticating easier for those with Microsoft accounts.
Mojang account authentication is currently not supported.
However, you can still authenticate by going through the Mojang authentication scheme and retrieving the access token.

.. automodule:: packets.utils.gat
    :members:

Varints
------------------------------
This module processes the many varints (such as packet ids) thrown by the packet stream and decodes them.

.. automodule:: packets.utils.varint
    :members:

