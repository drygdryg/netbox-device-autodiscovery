"""
Avaya IP office telephone exchange phone list extractor
Uses SNMP to communicate with the telephone exchange
"""

import subprocess
from typing import Optional

from logger import log
from shared_objects import netbox_template


class Module:
    def __init__(self, config: dict):
        self.config = config

    def run(self) -> Optional[dict]:
        """Returns dictionary of NetBox objects to verify, and create or update"""
        pbx_address = self.config['pbx_address']
        snmp_community = self.config['snmp_community']
        p = subprocess.run(
            f'snmptable -v 1 -c {snmp_community} {pbx_address} TCP-MIB::tcpConnTable', shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='ascii'
        )
        if p.returncode != 0:
            log.warning(f'Error when executing the snmptable command:\n{p.stderr}')
            return
        table_rows = list(line.strip().split() for line in p.stdout.splitlines()[3:])
        online_phones = [p[3] for p in table_rows if p[0] == 'established']

        nb_objects = {
            'manufacturers': [netbox_template.manufacturer('Avaya')],
            'device_types': [netbox_template.device_type('Avaya', 'VoIP phone')],
            'devices': [], 'interfaces': [], 'ip_addresses': []
        }
        for ip in online_phones:
            nb_objects['devices'].append(
                netbox_template.device(name=ip, device_role='VoIP phone', manufacturer='Avaya', model='VoIP phone'))
            nb_objects['interfaces'].append(netbox_template.device_interface(device=ip, name='vNIC'))
            nb_objects['ip_addresses'].append(
                netbox_template.ip_address(ip + '/32', device=ip, interface='vNIC'))

        return nb_objects
