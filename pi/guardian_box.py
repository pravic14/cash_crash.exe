#!/usr/bin/env python3
"""cash_crash.exe trusted-contact box: display-only LEDs plus a scoped decision button."""

import argparse
import json
import os
import threading
import time
import urllib.error
import urllib.request

from gpiozero import Button, LED

# websocket-client is the only non-standard dependency; gpiozero is already installed on this Pi.
try:
    import websocket
except ImportError as exc:
    raise SystemExit(
        "Missing websocket-client. Do not bypass the socket with button-only approval. "
        "If you have the Pi password, install it with: python3 -m pip install --user websocket-client"
    ) from exc

GREEN_PIN, AMBER_PIN, RED_PIN = 17, 22, 27
APPROVE_PIN, DECLINE_PIN = 23, 24
COOLDOWN_SECONDS = 60


class GuardianBox:
    def __init__(self, host: str, secret: str):
        self.host = host
        self.secret = secret
        self.green, self.amber, self.red = LED(GREEN_PIN), LED(AMBER_PIN), LED(RED_PIN)
        # pull_up=True means each button is wired GPIO-to-GND and reads pressed when grounded.
        self.approve = Button(APPROVE_PIN, pull_up=True, bounce_time=0.1)
        self.decline = Button(DECLINE_PIN, pull_up=True, bounce_time=0.1)
        self.lock = threading.Lock()
        self.hold_id = None
        self.cooldown_ends_at = 0.0
        self.approve.when_pressed = lambda: self.submit_decision(True)
        self.decline.when_pressed = lambda: self.submit_decision(False)
        self.all_off()

    def all_off(self):
        self.green.off()
        self.amber.off()
        self.red.off()

    def show_verdict(self, verdict: str):
        # LEDs are an output only: no LED state can authorise a payment.
        self.all_off()
        {"ALLOW": self.green, "HOLD": self.amber, "DENY": self.red}.get(verdict, self.red).on()

    def handle_status(self, raw_message: str):
        try:
            message = json.loads(raw_message)
            verdict = message["verdict"]
        except (json.JSONDecodeError, KeyError, TypeError):
            self.all_off()  # Untrusted/malformed socket data must not leave a misleading light on.
            return

        if verdict not in {"ALLOW", "HOLD", "DENY"}:
            self.all_off()
            return

        self.show_verdict(verdict)
        with self.lock:
            # Only P5 HOLD messages mint a local, short-lived button opportunity.
            if verdict == "HOLD" and message.get("matched_policy") == "P5" and message.get("proposal_id"):
                self.hold_id = str(message["proposal_id"])
                self.cooldown_ends_at = time.monotonic() + COOLDOWN_SECONDS
            else:
                self.hold_id = None
                self.cooldown_ends_at = 0.0

    def submit_decision(self, approve: bool):
        with self.lock:
            proposal_id = self.hold_id
            ready_at = self.cooldown_ends_at

        # The Pi fails closed: no valid P5 hold, cooldown, or network issue means no POST.
        if not proposal_id or time.monotonic() < ready_at:
            return

        body = json.dumps({"approve": approve, "channel": "trusted_contact"}).encode("utf-8")
        request = urllib.request.Request(
            f"http://{self.host}:8002/payments/{proposal_id}/decision",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Trusted-Contact": self.secret,  # Header prevents secret exposure in URLs/logs.
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                reply = json.loads(response.read().decode("utf-8"))
            verdict = reply.get("verdict")
            if verdict in {"ALLOW", "HOLD", "DENY"}:
                self.show_verdict(verdict)
            else:
                self.all_off()
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
            self.all_off()
        finally:
            # Each hold receives one local decision attempt; later state comes from the server socket.
            with self.lock:
                self.hold_id = None
                self.cooldown_ends_at = 0.0

    def run(self):
        url = f"ws://{self.host}:8002/ws"
        backoff = 1
        while True:
            # Socket has no decision authority; it is solely the source of display state/eligible holds.
            client = websocket.WebSocketApp(
                url,
                on_message=lambda _ws, message: self.handle_status(message),
                on_error=lambda _ws, _error: self.all_off(),
                on_close=lambda _ws, _code, _reason: self.all_off(),
            )
            client.run_forever(ping_interval=25, ping_timeout=10)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)


def main():
    parser = argparse.ArgumentParser(description="cash_crash.exe trusted-contact Pi box")
    parser.add_argument("--host", required=True, help="Laptop Wi-Fi IP running the port-8002 demo server")
    args = parser.parse_args()
    secret = os.environ.get("TRUSTED_CONTACT_KEY")
    if not secret:
        raise SystemExit("Set TRUSTED_CONTACT_KEY in the shell; never hard-code or commit the device secret.")
    GuardianBox(args.host, secret).run()


if __name__ == "__main__":
    main()
