# Bticino C300X — Home Assistant Integration

Custom integration for the **Bticino Classe 300X** video door entry system (videocitofono).

After an initial one-time cloud setup, the integration operates **entirely on the local network** via the OWN (Open Web Net) protocol — no cloud dependency at runtime.

## Features

- **Config flow UI**: enter your myhomeweb.com credentials once; plant, gateway, devices and local IP are discovered automatically
- **Local-only runtime**: all commands are sent directly to the gateway over TCP (OWN protocol, port 20000)
- **Dynamic button entities**: devices are read from the gateway configuration (conf.xml + archive.xml), so any activation configured in the official app appears automatically
- Typical entities: **Serratura** (entrance lock) and any gate/relay configured as an activation (e.g. *Apre cancello*)

## Installation

### HACS (recommended)

1. Open HACS → Integrations → ⋮ → Custom repositories
2. Add `https://github.com/Mirmanero/ha-bticino_c300x` as type **Integration**
3. Search for "Bticino C300X" and install
4. Restart Home Assistant

### Manual

Copy the contents of this repository into `config/custom_components/bticino_c300x/`.

## Configuration

1. Go to **Settings → Devices & Services → Add Integration**
2. Search for **Bticino C300X**
3. Enter your myhomeweb.com email and password
4. Confirm the gateway's local IP address (pre-filled automatically)

## How it works

| Phase | What happens |
|-------|-------------|
| Config flow step 1 | Logs into myhomeweb.com, fetches plant, gateway, OWN password, device list and local IP |
| Config flow step 2 | Shows discovered IP (editable) and a summary of found devices |
| Runtime | Zero cloud calls — button presses send OWN frames directly to the gateway |

## Requirements

- Bticino Classe 300 X (C300X) gateway on the local network
- An account on [myhomeweb.com](https://www.myhomeweb.com) with at least one plant configured
- Home Assistant 2024.1 or later

## OWN command reference

| Device | CID | Frame sent on press |
|--------|-----|---------------------|
| Serratura (entrance lock) | 10060 | `*8*19*{addr}##` → `*8*20*{addr}##` |
| Cancello / gate relay | 3008 | `*8*19*{addr}##` → `*8*20*{addr}##` |
| Alt relay | 2009 | `*8*21*{addr}##` → `*8*22*{addr}##` |
