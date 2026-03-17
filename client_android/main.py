from __future__ import annotations

import asyncio
import httpx
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput

from shared.crypto_utils.keys import IdentityKeyPair, b64e
from shared.protocol.client_session import SecureSession

API_BASE = "https://your-api.example.com/api"


class AndroidSecureStore:
    """Placeholder for Android Keystore integration via pyjnius/buildozer bridge."""

    def __init__(self) -> None:
        self.memory: dict[str, str] = {}

    def set(self, key: str, value: str) -> None:
        self.memory[key] = value

    def get(self, key: str) -> str | None:
        return self.memory.get(key)


class MessengerWidget(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", **kwargs)
        self.store = AndroidSecureStore()
        self.identity = IdentityKeyPair.generate()
        self.session: SecureSession | None = None

        self.peer = TextInput(hint_text="Recipient username")
        self.message = TextInput(hint_text="Message")
        self.status = Label(text="Ready")

        send_button = Button(text="Send encrypted")
        send_button.bind(on_press=lambda _: asyncio.run(self.send_message()))

        self.add_widget(self.peer)
        self.add_widget(self.message)
        self.add_widget(send_button)
        self.add_widget(self.status)

    async def send_message(self) -> None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token = self.store.get("access_token")
            headers = {"Authorization": f"Bearer {token}"}
            prekey = await client.get(f"{API_BASE}/users/{self.peer.text}/prekey", headers=headers)
            prekey.raise_for_status()
            if not self.session:
                self.session = SecureSession(self.identity, prekey.json()["identity_key"])

            envelope = self.session.encrypt_for_transport("me", self.peer.text, self.message.text)
            resp = await client.post(f"{API_BASE}/messages", headers=headers, json=envelope)
            resp.raise_for_status()
            self.status.text = "Encrypted message sent"


class AndroidMessengerApp(App):
    def build(self):
        return MessengerWidget()


if __name__ == "__main__":
    AndroidMessengerApp().run()
