import mcprot
import asyncio
import logging

logging.basicConfig(level = logging.INFO)

stream = mcprot.PacketStream('localhost', 25565)

loop = asyncio.get_event_loop()
result = loop.run_until_complete(stream.get_status())
print(result)

