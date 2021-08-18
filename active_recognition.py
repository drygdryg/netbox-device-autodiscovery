import re
from typing import Optional

import requests

from utils import Device


def safe_http_get(url, params: dict = None, timeout=3) -> Optional[requests.Response]:
    try:
        r = requests.get(url, params=params, timeout=timeout, verify=False)
    except requests.exceptions.RequestException:
        return
    else:
        return r


def recognize_by_http(ip: str, port=80, http_timeout=3) -> Optional[Device]:
    """Recognize device with a web interface: printers, routers, etc."""
    base_url = f'http://{ip}:{port}'
    r = safe_http_get(f'{base_url}/', timeout=http_timeout)
    if not r:
        return

    # Recognize device by the response body
    if 'SeWoo Ethernet IP Config' in r.text:
        return Device('SeWoo', 'printer', 'Printer', None)
    elif (('TP-Link Corporation Limited.' in r.text) or ('TP-Link Technologies Co., Ltd.' in r.text)) and \
         ('g_Lan = 385;' in r.text):
        return Device('TP-Link', 'switch', 'Switch', None)
    elif ('Zebra Technologies' in r.text) and (match := re.search(r'ZTC ([\w-]+)', r.text)):
        return Device('Zebra', match.group(1), 'Printer', None)
    elif 'KYOCERA MITA' in r.text:
        return Device('KYOCERA', 'printer', 'Printer', None)
    elif match := re.search(r'HP(?: Color)? LaserJet MFP (\w+)', r.text):
        return Device('HP', f'LaserJet {match.group(1)}', 'MFP', None)
    elif match := re.search(r'HP(?: Color)? LaserJet Pro MFP (\w+)', r.text):
        return Device('HP', f'LaserJet Pro {match.group(1)}', 'MFP', None)

    # Recognize device by the Server response header
    if 'Server' in r.headers:
        server_header = r.headers['Server']
        if match := re.search(r'HP (DesignJet \w+) MFP', server_header):
            return Device('HP', match.group(1), 'MFP', None)
