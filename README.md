# Arpmon

A simple tool to detect devices on LAN

# Configuration

1. Clone repo: `git clone https://github.com/lucas-engen/arpmon.git`
   1.1) Install libpcap `sudo apt install libpcap-dev`
   1.2) Install libjson-c `sudo apt install libjson-c-dev`
2. Build project: `make`
3. Install program: `python install.py` as root
4. Create `machine.json` on the same install path of arpmon
5. Configure `machine.json` to map mac addresses to strings
