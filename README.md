# Auto device discovery script for NetBox
## Overview
Script for automatically discovering network devices and adding them to NetBox. Supports multiple data sources and various types of devices (router, switch, printer, MFP, Wi-Fi and other).
## Dependencies
As root

`pip3 install pynetbox toml lxml python-nmap pysnmp`

`apt install nmap`
## Setup
Copy `configuration.example.toml` to `configuration.toml` and set the necessary settings.  
The program has a modular system. You can enable or disable modules, change the order of their launch. To do this, change the `modules` list in the `configuration.toml` (you can comment out a module name to disable it).  
Each module has its own configuration, it's stored in a separate TOML table with name of the module. For example, configuration for the module `nmap_network_scanner` will look like this:
```toml
[nmap_network_scanner]
nmap_guess_os = true
nmap_additional_args = "-T4"
snmp_communities = ["public", "jsad084Ji0mapq"]
snmp_retry_count = 2
```
The following modules are currently implemented:
- `nmap_network_scanner`: scans NetBox prefixes using Nmap and tries to recognize found devices using various techniques;
- `avaya_ip_office_phones_enumerator`: connects to Avaya IP Office IP-PBX via SNMP protocol and receives list of connected devices/VoIP-phones.
## Usage
When using `nmap_network_scanner` module, run the script as a superuser
```
usage: python3 run.py [-h] [-c] [-v]

optional arguments:
  -h, --help     show this help message and exit
  -c, --cleanup  Remove all auto discovered objects which support tagging from NetBox and exit. This is helpful if you want to start fresh or stop using this script.
  -v, --verbose  Increase verbosity level This overrides the log level in the settings file. Intended for debugging purposes only
```
## Author
Victor Golovanenko ([drygdryg](https://github.com/drygdryg))
## Acknowledgements
Thanks to [Raymond Beaudoin](https://github.com/synackray) for the ideas and mechanisms implemented in [vcenter-netbox-sync](https://github.com/synackray/vcenter-netbox-sync)