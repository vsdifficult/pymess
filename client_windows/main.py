from __future__ import annotations

import asyncio
import sys

import httpx
from PyQt6.QtWidgets import QApplication, QLabel, QPushButton, QTextEdit, QVBoxLayout, QWidget

from shared.crypto_utils.keys import IdentityKeyPair
from shared.protocol.client_session import SecureSession

API_BASE = "https://your-api.example.com/api"


class WindowsSecureStore:
    """Use `win32crypt.CryptProtectData` in production for DPAPI-backed secrets."""

    def __init__(self) -> None:
        self.memory: dict[str, str] = {}

    def set(self, key: str, value: str) -> None:
        self.memory[key] = value

    def get(self, key: str) -> str | None:
        return self.memory.get(key)


class ChatWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyMess Secure Windows Client")

        self.store = WindowsSecureStore()
        self.identity = IdentityKeyPair.generate()
        self.session: SecureSession | None = None

        self.peer_input = QTextEdit()
        self.peer_input.setPlaceholderText("Recipient username")
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Message")
        self.status = QLabel("Ready")
        send_btn = QPushButton("Send encrypted")
        send_btn.clicked.connect(lambda: asyncio.run(self.send_message()))

        layout = QVBoxLayout()
        layout.addWidget(self.peer_input)
        layout.addWidget(self.message_input)
        layout.addWidget(send_btn)
        layout.addWidget(self.status)
        self.setLayout(layout)

    async def send_message(self) -> None:
        peer = self.peer_input.toPlainText().strip()
        plaintext = self.message_input.toPlainText().strip()
        token = self.store.get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

        async with httpx.AsyncClient(timeout=10.0) as client:
            prekey = await client.get(f"{API_BASE}/users/{peer}/prekey", headers=headers)
            prekey.raise_for_status()
            if not self.session:
                self.session = SecureSession(self.identity, prekey.json()["identity_key"])
            envelope = self.session.encrypt_for_transport("me", peer, plaintext)
            resp = await client.post(f"{API_BASE}/messages", headers=headers, json=envelope)
            resp.raise_for_status()

        self.status.setText("Encrypted message sent")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatWindow()
    window.show()
    sys.exit(app.exec())
