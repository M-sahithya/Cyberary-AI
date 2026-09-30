import asyncio
import json
import websockets


async def main():
    uri = "ws://127.0.0.1:8000/ws/security-events"

    print("Connecting to WebSocket...")

    async with websockets.connect(uri) as ws:
        print("WebSocket connected!")

        message = await ws.recv()

        print("\nReceived:")
        print(json.dumps(json.loads(message), indent=2))

        print("\nWaiting for communication security notification...")

        while True:
            message = await ws.recv()
            data = json.loads(message)

            print("\nReceived:")
            print(json.dumps(data, indent=2))

            if data.get("type") == "communication_security_notification":
                print("\nCommunication Security Notification received!")
                break


if __name__ == "__main__":
    asyncio.run(main())