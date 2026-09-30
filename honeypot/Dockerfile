# Honeypot Placeholder Dockerfile
# This will be expanded in Phase 3 with Cowrie integration

FROM python:3.11-slim

WORKDIR /honeypot

# Install basic dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    openssh-server \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create a simple TCP listener placeholder
RUN pip install --no-cache-dir twisted

# Create placeholder script
RUN echo '#!/usr/bin/env python3\n\
import asyncio\n\
import logging\n\
\n\
logging.basicConfig(level=logging.INFO)\n\
logger = logging.getLogger("honeypot-stub")\n\
\n\
async def handle_connection(reader, writer):\n\
    addr = writer.get_extra_info("peername")\n\
    logger.info(f"Connection from {addr}")\n\
    writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\\r\\n")\n\
    await writer.drain()\n\
    try:\n\
        data = await asyncio.wait_for(reader.read(1024), timeout=30)\n\
        logger.info(f"Received from {addr}: {data}")\n\
    except asyncio.TimeoutError:\n\
        pass\n\
    finally:\n\
        writer.close()\n\
        await writer.wait_closed()\n\
\n\
async def main():\n\
    server = await asyncio.start_server(handle_connection, "0.0.0.0", 2222)\n\
    logger.info("Honeypot stub listening on port 2222")\n\
    async with server:\n\
        await server.serve_forever()\n\
\n\
if __name__ == "__main__":\n\
    asyncio.run(main())\n\
' > /honeypot/stub.py

EXPOSE 2222

CMD ["python", "/honeypot/stub.py"]
