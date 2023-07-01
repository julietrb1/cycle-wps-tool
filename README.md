# Cycle

> ## No longer under active development.
>
>  📚 This repository has been archived, as it served its purpose and is no longer under active development. Good to see you, though!

> A WPS audit late-night project that grew into something far greater... for me, anyways.

Cycle is a draft-quality, thrown-together Python script which uses [mdk4](https://github.com/aircrack-ng/mdk4), [Reaver](https://github.com/t6x/reaver-wps-fork-t6x), and [wash](https://github.com/t6x/reaver-wps-fork-t6x#wash-usage) to perform WPS PIN attacks on a given AP, and then performs a suite of attacks on it if it locks. If it unlocks, continue PIN attacks. Rinse and repeat.

## Features

- Configurable attack selection
- MAC changing to spoof as client on AP
- Colour-coded fancy console and file logging
- Output of useful statistics while attacking (such as CPU and DoS attacks)
- Simple, low-requirement script
- Designed to be as environment-agnostic (within reason)

## Installation

Requirements include:

- A POSIX-compliant system ([Kali Linux](https://www.kali.org) if you want to make things easy).
- A wireless adapter capable of monitor mode and packet injection (which is covered by [many guides](https://kennyvn.com/best-wireless-adapters-kali-linux/)).
- Python 3.x (this was tested with Python 3.7.7)
- 2 CPUs
- A sane amount of RAM and disk space (but it really doesn't use much)
- Tools likely installable through `apt-get`, `yum`, or similar:
    - `mdk4`
    - `reaver`
    - `wash`
    - `macchanger` (if you wish to use the MAC changing function of Cycle)
    - `virtualenv` (from `pip` - only needed if you complete the optional step 2 below)

*Note: The following assumes a macOS/Linux environment*

**Step 1: Clone the repository**

```bash
git clone https://github.com/dylanjboyd/cycle-wps-tool.git
cd cycle-wps-tool
```

**Step 2 (recommended): Create and activate a `virtualenv`**

```bash
python3 -m venv env
source env/bin/activate
```

**Step 3: Install `pip` requirements**

```bash
pip install -r requirements.txt
```

## Usage

```
usage: cycle.py [-h] [-b BSSID] [-w WAIT_TIME] [-c CHANNEL] [-N] [-S]
                [-i INTERFACE] [-v] [-s] [-m MAC_ADDRESS] [-1] [-2] [-3] [-4]
                [-9 MINS]

optional arguments:
  -h, --help            show this help message and exit
  -b BSSID, --bssid BSSID
                        BSSID of target network
  -w WAIT_TIME, --wait-time WAIT_TIME
                        time (secs) to wait between lock checks when attacking
  -c CHANNEL, --channel CHANNEL
                        channel of target BSSID(s)
  -N, --send-nacks      sending NACKS - disabled by default to speed up some
                        attacks
  -S, --small           enables small subgroup confinement attack on Diffie-
                        Hellman
  -i INTERFACE, --interface INTERFACE
                        the interface to use in attacks (default: wlan0mon)
  -v, --verbose         show (and log) more detailed output
  -s, --spoof-mac       use a spoofed MAC (random if -m not provided)
  -m MAC_ADDRESS, --mac-address MAC_ADDRESS
                        the fake MAC to use with -s
  -1, --dos             run DoS attacks when AP locked
  -2, --deauth          run deauth attacks when AP locked
  -3, --michael         run Michael attacks when AP locked
  -4, --eapol           run EAPOL attacks when AP locked
  -9 MINS, --random-attacks MINS
                        cycle through random attacks at this set interval
                        (mins)
```

## Background

In my exploration through desire to learn more about the intricacies of wireless security, auditing, and assessment, I did a lot of learning, reading, and experimenting with tools such as mdk3, mdk4, reaver, wifite, airodump-ng, airmon-ng, aireplay-ng... (the list goes on).

What I found in my amateur, playful research is that there is a **massive** amount of fragmentation and missing pieces in information posted on the **very real, very current** weaknesses of wireless standards such as WPS.

Then, I found some gold mines! Some people had [talked about ways to automate getting around WPS locks](https://forums.kali.org/showthread.php?25459-Force-an-AP-to-reboot&p=46155#post46155), so that one could start a tool and have it unlock before your eyes. However, I couldn't find any such tool that matched my requirements and expecations, even though these conversations were from years back.

These discussions involved having a tool run a WPS PIN attack on an AP and then, if and when the AP locks, run one or more known and semi-proven attacks on said AP to force it to reboot or confuse it. If it unlocks, continue. Rinse and repeat.

I found tools such as [VMR-MDK-K2-2017R-012x4](https://github.com/chunkingz/VMR-MDK-K2-2017R-012x4) (what a name...) which claimed to do something along the same lines, but it imposed all sorts of requirements on the executing environment (which excludes SSH environments, for example).

[besside-ng](https://www.aircrack-ng.org/doku.php?id=besside-ng) does something along these lines for standard WPA handshake attacks, cycling between deauthenticating all clients of an AP in an attempt to capture a handshake. Obviously, this doesn't cover WPS.

[wifite2](https://github.com/derv82/wifite2) covers besside-ng functionality around handshake attacks, but also supports WPS Pixie Dust, NULL, and PIN attacks. However, it doesn't perform any kind of attack on the router during WPS attacks. If an AP is locked, it gives up.

This is where Cycle comes in to save the day. Hopefully. It aggregates ideas from these tools, and consolidates them all into an uncomplicated, low-requirement Python 3.x script.

## Extra for Experts

If you wish to see more on how Cycle works internally, head over to [Internals](./INTERNALS.md) for more.

## FAQs

### Will this be maintained regularly?

Don't count on it. If it is, consider it a bonus. This was created solely as an educational exercise to broaden my understanding of technology. Do I want you to fork this repo if you think you can make it better and go your own way, so you can make the world a better, more secure place? Absolutely.

### Do I endorse using this tool to break the law or violate personal/moral rights?

Absolutely not. This tool was used on my own router, and likewise you should only use it on systems that you have permission to test. Unless you like the sound of a [$600,000 fine](https://edition.cnn.com/2014/10/03/travel/marriott-fcc-wi-fi-fine/index.html). Yes, that's USD.

### Is this tool one of a kind?

I can't promise that it is, but I did spend a decent amount of time researching available tools and scripts across the interwebs, and didn't come up with much. As far as I know, no tool does exactly what Cycle does.

### How did you come up with the name?

Honestly, I was rather tired when I came up with the concept for this tool, so I drew a picture in my head, stood back, and called it as it looked. A cycle. Inventive, right? My award is in the mail.

### Why is this being published as open source?

I love the concept and execution of open source; I can quite honestly say that it has changed the world. Most of what I have learned and code written in Cycle would not have been possible if not for the collaborative, community-driven effort of open source development. Do I want to join in the fun? Absolutely.

### Anything else?

I hope you're having an exquisite and blessed day. That is all.

## License and Disclaimer

Please see the [License](./LICENSE.md) for legal permissions and restrictions.
