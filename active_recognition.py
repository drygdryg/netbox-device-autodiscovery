from typing import Optional

import requests

from utils import Device


def safe_http_get(url, params: dict = None, timeout=3) -> Optional[requests.Response]:
    try:
        r = requests.get(url, params=params, timeout=timeout)
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

    if 'SeWoo Ethernet IP Config' in r.text:
        return Device('SeWoo', 'printer', 'Printer', None)
    elif ('Zebra Technologies' in r.text) and ('ZTC ' in r.text):
        return Device('Zebra', 'printer', 'Printer', None)
    elif 'KYOCERA MITA' in r.text:
        return Device('KYOCERA', 'printer', 'Printer', None)
