# ARPScanner
Network Host Discovery With ARP Scanning  

This is a simple Python script designed to scan a network range to find active devices via the ARP protocol. It is important to note that the script is not very fast due to the lack of multi-threading.
This script is only useful for learning network socket programming in Python and for modeling and implementing it on a small network.

Note 1: I think the psutil library is not installed by default on your system and you need to install it using APT or PIP.

Note 2: Due to the use of raw sockets, the script must be run with root access on Linux

## Usage

```markdown

sudo python3 arpscanner.py -i <iface> -r <network range>
sudo python3 arpscanner.py -i vboxnet0 -r 192.168.56.0/24
```
