import mcprot
import asyncio
import logging

logging.basicConfig(level = logging.INFO)

stream = mcprot.PacketStream('localhost', 25565, 756)

@stream.packet_handler(15)
async def handle_chat(packet):
    print("Chat: ", packet.packet_data)

if __name__ == '__main__':
    print("Starting Stream.")
    loop = asyncio.get_event_loop()
    loop.run_until_complete(stream.connect('cappy'))
