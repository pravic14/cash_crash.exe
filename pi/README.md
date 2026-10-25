# pi/ — D, Hardware

The trusted-contact box. A family member co-approves a HIGH-risk payment. Breadboard and jumper wires only. No soldering. No screen, sensors, or case until the rest of the demo works.

The Pi is a **WebSocket client**. The backend stays on the laptop. If the Pi dies, the ops dashboard buttons do the same job. A borrowed Pi 5 is the fallback if a 3B+ misbehaves (Hackathons UK: hackuk.org/raspi). The hardware stall opens 12:30.

## File to add

`guardian_box.py` — gpiozero. Not built yet. It will connect out to `server/ws.py`. Decline and approve already work over HTTP: `POST /payments/{id}/decision`. Approving a HIGH hold also needs the header `X-Trusted-Contact`. The customer page cannot send that header.

| Part | BCM pin |
| --- | --- |
| Green LED (approved) | 17 |
| Amber LED (on hold, waiting for trusted contact, blinks) | 22 |
| Red LED (blocked) | 27 |
| Active buzzer (scam alert) | 18 |
| Button APPROVE | 23 (pull-up) |
| Button DECLINE | 24 (pull-up) |

330Ω resistor on each LED.

## Demo beat

Margaret's scam payment: lights step red as each guard fires, the explainer cites `safe-account`, the amber LED blinks, and the judge presses DECLINE.
