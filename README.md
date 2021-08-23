# Auto device discovery script for NetBox
## Overview
Script for scanning NetBox IP prefixes, automatically detecting devices, and registering them in NetBox
## Author
Victor Golovanenko (drygdryg)
## Setup
Copy `configuration.example.toml` to `configuration.toml` and set the necessary settings
## Usage
```
usage: run.py [-h] [-c] [-v]

optional arguments:
  -h, --help     show this help message and exit
  -c, --cleanup  Remove all auto discovered objects which support tagging from NetBox and exit. This is helpful if you want to start fresh or stop using this script.
  -v, --verbose  Increase verbosity level This overrides the log level in the settings file. Intended for debugging purposes only
```