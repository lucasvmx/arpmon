# Script to install arpmon

from os import getuid, system
from os.path import exists

service_name = "arpmon"
service_defs = '''[Unit]
Description=ArpMon network monitoring tool

[Service]
WorkingDirectory=$wd
Type=simple
ExecStart=$es $iface $gip
RestartSec=5
Restart=always
SuccessExitStatus=0

[Install]
WantedBy=multi_user.target
'''

if getuid() != 0:
    print("[!] Need root permissions")
    exit(5)

service_file_path = f'/etc/systemd/system/{service_name}.service'
print(f"[*] Installing service to {service_file_path}")

if exists(service_file_path):
    print(f"[!] Service already installed.")
    exit(0)

ip = input("Install path: ")
if exists(ip):
    print("[!] Directory already exists")

gip = input("Gateway ip: ")
iface = input("Interface name: ")

# Copy all files to install path
service_defs = service_defs.replace("$wd", ip)
service_defs = service_defs.replace("$es", f"{ip}/{service_name}")
service_defs = service_defs.replace("$iface", iface)
service_defs = service_defs.replace("$gip", gip)

system(f"mkdir -p {ip}")
system(f"cp {service_name} {ip} -r -vv")

# Create service
# Write service settings to disk
with open(service_file_path, "w") as file:
    file.write(service_defs)

# Enable autorun
system(f"systemctl enable {service_name}")

# Execute service
system(f"systemctl start {service_name}")


    

