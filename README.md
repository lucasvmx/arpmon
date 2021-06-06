# Arpmon
A simple tool to detect devices on LAN

# Configuration
  1) Clone repo: ```git clone https://github.com/lucas-engen/arpmon.git```
  2) Build project: ```make```
  3) Install program: ```python install.py``` as root
  4) Execute: ```systemctl daemon-reload && systemctl enable arpmon && systemctl start arpmon```
  5) Check service status: ```systemctl status arpmon```

