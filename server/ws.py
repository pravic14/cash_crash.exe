"""WebSocket fan-out for the Pi and the ops screen.

The HTTP approve and decline routes do the same job when nobody is connected.
"""

from __future__ import annotations

import json

from fastapi import WebSocket


class Hub:
    def __init__(self) -> None:
        self.clients: set[WebSocket] = set()

    async def connect(self, socket: WebSocket) -> None:
        await socket.accept()
        self.clients.add(socket)

    def disconnect(self, socket: WebSocket) -> None:
        self.clients.discard(socket)

    async def broadcast(self, payload: dict) -> None:
        dead: list[WebSocket] = []
        message = json.dumps(payload)
        for socket in self.clients:
            try:
                await socket.send_text(message)
            except Exception:
                dead.append(socket)
        for socket in dead:
            self.disconnect(socket)


hub = Hub()
