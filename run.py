import argparse
import re
from collections import namedtuple, defaultdict
from typing import List, Optional

import pynetbox
import requests as requests
from nmap import PortScanner, PortScannerError

from configuration import config
from netbox_templates import NetBoxTemplate
from utils import args2str, format_slug, remove_duplicates
from logger import log

nb = pynetbox.api(url=config['netbox']['url'], token=config['netbox']['api_token'])

NB_DEFAULT_SITE = config['netbox']['default_devices_site']

# Properties of NetBox object types
NetBoxObjectProperties = namedtuple('NetBoxObjectProperties', ('api_app', 'api_model', 'key'))
NETBOX_OBJECTS_PROPERTIES = {
    "device_roles": NetBoxObjectProperties("dcim", "device-roles", "name"),
    "device_types": NetBoxObjectProperties("dcim", "device-types", "model"),
    "devices": NetBoxObjectProperties("dcim", "devices", "name"),
    "interfaces": NetBoxObjectProperties("dcim", "interfaces", "name"),
    "ip_addresses": NetBoxObjectProperties("ipam", "ip-addresses", "address"),
    "manufacturers": NetBoxObjectProperties("dcim", "manufacturers", "name"),
    "platforms": NetBoxObjectProperties("dcim", "platforms", "name"),
    "sites": NetBoxObjectProperties("dcim", "sites", "name"),
    "tags": NetBoxObjectProperties("extras", "tags", "name")
}
# The order in which NetBox objects should be created
NETBOX_OBJECTS_CREATION_ORDER = ('platforms', 'manufacturers', 'device_types', 'devices', 'interfaces', 'ip_addresses')
# The order in which outdated NetBox objects should be cleaned up
NETBOX_OBJECTS_DELETION_ORDER = ('ip_addresses', 'interfaces', 'devices', 'device_types')


def verify_prerequisites():
    """Checks for the presence of all necessary NetBox objects and creates them"""
    prerequisites = {
        'device_roles': [
            {'name': 'PC', 'slug': 'pc'},
            {'name': 'Router', 'slug': 'router'},
            {'name': 'Switch', 'slug': 'switch'},
            {'name': 'Printer', 'slug': 'printer'},
            {'name': 'MFP', 'slug': 'mfp'}
        ],
        'sites': [
            {
                'name': NB_DEFAULT_SITE,
                'slug': format_slug(NB_DEFAULT_SITE)
            }
        ],
        'tags': [
            {
                'name': 'Autodiscovered',
                'slug': 'autodiscovered',
                'description': 'Object automatically discovered by the netbox-device-autodiscovery script'
            },
            {
                'name': 'Do not autodiscover', 'slug': 'do-not-autodiscover',
                'description': "Tag that, when attached to an IP prefix, disables it's discovery "
                               "by the netbox-autodiscovery program"
            }
        ]
    }
    log.info("Verifying all prerequisite objects exist in NetBox.")
    for requirement_type in prerequisites:
        log.debug(
            "Checking NetBox has necessary %s objects.", requirement_type
        )
        for requirement in prerequisites[requirement_type]:
            create_or_update_nb_obj(requirement_type, requirement)
    log.info("Finished verifying prerequisites.")


def prepare_pynetbox_result(query_result: dict) -> dict:
    """Prepares pynetbox query result for comparison using compare_nb_objects function"""
    result = query_result.copy()
    for key in result.keys():
        if isinstance(result[key], pynetbox.core.response.Record):
            result[key] = result[key].__dict__
        elif isinstance(result[key], list):
            new_lst = [(i.__dict__ if isinstance(i, pynetbox.core.response.Record) else i) for i in query_result[key]]
            result[key] = new_lst
        if (key == 'tags') and (isinstance(result[key], dict)):
            result[key] = [result[key]]

        if isinstance(result[key], dict):
            result[key] = prepare_pynetbox_result(result[key])
    return result


def compare_nb_objects(dict1: dict, dict2: dict) -> bool:
    """Compares the key value pairs of two dictionaries returns True if they match, False otherwise"""
    for key in dict1.keys():
        if key not in dict2.keys():
            return False
        elif key == 'tags':
            if set(tag['name'] for tag in dict1[key]) != set(tag['name'] for tag in dict2[key]):
                return False
        elif key in ('status', 'type'):
            if dict1[key] != dict2[key]['value']:
                return False
        elif isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
            if not compare_nb_objects(dict1[key], dict2[key]):
                return False
        elif isinstance(dict1[key], list) and isinstance(dict2[key], list):
            if not all([bool(item in dict2[key]) for item in dict1[key]]):
                return False
        elif dict1[key] != dict2[key]:
            return False
    return True


def fetch_assigned_interface_id(obj: dict) -> dict:
    """Fetch assignment interface ID for IP address based on assignment dictionary"""
    q_interface = obj["assigned_object"]["name"]
    q_device = obj["assigned_object"]["device"]["name"]
    res = nb.dcim.interfaces.get(**{'device': q_device, 'name': q_interface})
    if res:
        obj["assigned_object_id"] = res.id
    return obj


def create_or_update_nb_obj(obj_type: str, obj: dict) -> int:
    """
    Checks whether a NetBox object exists and matches.
    If object does not exist or does not match, it will be created or updated.

    :param obj_type: NetBox object type, must match keys in self.obj_map
    :param obj: object of obj_type
    :return: ID of the existing or created NetBox object
    """
    query_key = NETBOX_OBJECTS_PROPERTIES[obj_type].key
    api_app = NETBOX_OBJECTS_PROPERTIES[obj_type].api_app
    api_model = NETBOX_OBJECTS_PROPERTIES[obj_type].api_model
    query_params = {query_key: obj[query_key]}
    if obj_type == "interfaces":
        query_params['device'] = obj['device']['name']
    elif obj_type == "device_types":
        query_params['manufacturer'] = format_slug(obj['manufacturer']['name'])

    existing_nb_obj = getattr(getattr(nb, api_app), api_model).get(**query_params)
    if existing_nb_obj:
        log.debug(
            "NetBox %s object '%s' already exists. Comparing values.",
            obj_type, obj[query_key]
        )
        if compare_nb_objects(obj, prepare_pynetbox_result(existing_nb_obj.__dict__)):
            log.info(
                "NetBox %s object '%s' match current values. Moving on.",
                obj_type, obj[query_key]
            )
        else:
            log.info(
                "NetBox %s object '%s' do not match current values.",
                obj_type, obj[query_key]
            )
            if obj_type == 'ip_addresses':
                log.debug(
                    "Obtaining NetBox ID of the assigned object to bind it to the %s object '%s'",
                    obj_type, obj[query_key]
                )
                obj = fetch_assigned_interface_id(obj)
            existing_nb_obj.update(obj)
        return existing_nb_obj.id
    else:
        log.info(
            "Netbox %s '%s' object not found. Requesting creation.",
            obj_type, obj[query_key]
        )
        if obj_type == 'ip_addresses':
            log.debug(
                "Obtaining NetBox ID of the assigned object to bind it to the %s object '%s'",
                obj_type, obj[query_key]
            )
            obj = fetch_assigned_interface_id(obj)
        created_nb_obj = getattr(getattr(nb, api_app), api_model).create(obj)
        return created_nb_obj.id


def scan_networks(prefixes: List[str]) -> Optional[dict]:
    """Scan given networks using the Network mapper and detect hardware platforms and operating systems"""
    # Initialize Nmap scanner
    try:
        nmap = PortScanner()
    except PortScannerError as error:
        log.error("Nmap scanner critical error occurred: %s", error.value)
        return
    nmap_arguments = ['-sS', '-O']
    if config['discovery']['nmap_guess_os']:
        nmap_arguments.append('--osscan-guess')
    nmap_arguments.extend(config['discovery']['nmap_additional_args'].split(' '))

    log.info('Network scanning started')
    scan_results = nmap.scan(args2str(prefixes), arguments=args2str(nmap_arguments), sudo=True)
    return scan_results['scan']


Device = namedtuple('Device', ('manufacturer', 'model', 'role', 'platform'), defaults=(None, None, None, None))


def recognize_device(ip_addr: str, open_ports: List[int], os_matches: List[dict]) -> Optional[Device]:
    """
    Recognizes device model, operating system, based on the result of scanning the host using Nmap

    :param ip_addr: IP addresses of the host
    :param open_ports: List of open TCP ports
    :param os_matches: Nmap OS detection results
    """
    os_match = os_matches[0]
    os_name = os_match['name']
    os_class = os_match['osclass'][0]
    os_class_type = os_class['type']
    if os_class_type == 'general purpose':
        # Microsoft Windows PC
        if (os_class['vendor'] == 'Microsoft') and (os_class['osfamily'] == 'Windows'):
            return Device('Generic', 'PC', 'PC', 'Windows')
        # Apple PC
        if (os_class['vendor'] == 'Apple') and (os_class['osfamily'] in ('OS X', 'Mac OS X')):
            return Device('Apple', 'PC', 'PC', 'macOS')
    elif os_class_type == 'switch':
        role = 'Switch'
        # Cisco switches
        if os_class['vendor'] == 'Cisco':
            manufacturer = 'Cisco'
            if os_name.startswith('Cisco Nexus'):
                model = re.match(r'Cisco (Nexus(?: \d+)?)', os_name).group(1)
                platform = os_class['osfamily']
                return Device(manufacturer, model, role, platform)
            elif os_name.startswith('Cisco Catalyst'):
                model = re.match(r'Cisco (Catalyst(?: [\w-]+)?) switch', os_name).group(1)
                platform = os_class['osfamily']
                return Device(manufacturer, model, role, platform)
    elif os_class_type == 'router':
        role = 'Router'
        if os_class['vendor'] == 'Cisco':
            manufacturer = 'Cisco'
            if os_name.startswith('Cisco IOS'):
                return Device(manufacturer, 'IOS router', role, os_class['osfamily'])
    elif os_class_type == 'printer':
        role = 'Printer'
        if os_class['vendor'] == 'HP':
            return Device('HP', 'printer', role, None)
        else:
            return Device('Generic', 'printer', role, None)
    elif os_class_type == 'specialized':
        pass
    # Generic cases
    if 80 in open_ports:
        try:
            r = requests.get(f'http://{ip_addr}/', timeout=3)
        except requests.exceptions.RequestException:
            pass
        else:
            if 'SeWoo Ethernet IP Config' in r.text:
                return Device('SeWoo', 'printer', 'Printer', None)
            elif ('Zebra Technologies' in r.text) and ('ZTC ' in r.text):
                return Device('Zebra', 'printer', 'Printer', None)
            elif 'KYOCERA MITA' in r.text:
                return Device('KYOCERA', 'printer', 'Printer', None)
    if 515 in open_ports:
        return Device('Generic', 'printer', 'Printer', None)


def process_scan_results(nmap_results: dict) -> dict:
    """Converts the results of an Nmap network scan to NetBox entities"""
    nbt = NetBoxTemplate(
        default_tags=[{
            'name': 'Autodiscovered'
        }]
    )
    log.info('Converting Nmap scan results to NetBox objects…')
    nb_objects = defaultdict(list)
    for ip, scan_results in nmap_results.items():
        log.info(f'Recognition of the device with IP {ip} is started…')
        if not scan_results['osmatch']:
            log.info(f'No OS matches found, IP {ip} skipped')
            continue

        open_ports = [port for port, qualities in scan_results['tcp'].items() if qualities['state'] == 'open'] if 'tcp' in scan_results else []
        recognized_device = recognize_device(ip, open_ports, scan_results['osmatch'])
        if not recognized_device:
            log.info('Failed to recognize the device, skipped')
            continue

        nb_objects['manufacturers'].append(nbt.manufacturer(recognized_device.manufacturer))
        nb_objects['device_types'].append(nbt.device_type(recognized_device.manufacturer, recognized_device.model))
        if recognized_device.platform:
            nb_objects['platforms'].append(nbt.platform(recognized_device.platform))

        # Use IP address as the device name
        device_name = ip
        nb_objects['devices'].append(
            nbt.device(
                name=device_name, device_role=recognized_device.role, manufacturer=recognized_device.manufacturer,
                model=recognized_device.model, site=NB_DEFAULT_SITE, platform=recognized_device.platform
            ))
        nb_objects['interfaces'].append(nbt.device_interface(device=device_name, name='vNIC'))

        dns_name = scan_results['hostnames'][0]['name'] if scan_results['hostnames'][0]['name'] else None
        nb_objects['ip_addresses'].append(
            nbt.ip_address(ip + '/32', device=device_name, interface='vNIC', dns_name=dns_name))
        log.info(
            'Device recognized: {}'.format(
                ', '.join('='.join((k, str(v))) for k, v in recognized_device._asdict().items()))
        )

    return {k: remove_duplicates(v) for k, v in nb_objects.items()}


def main():
    # Check prerequisites
    verify_prerequisites()

    # Obtain IP prefixes to scan, excluding prefixes with "Do not autodiscover" tag
    autodiscovery_disabled_tag = nb.extras.tags.get(slug='do-not-autodiscover')
    target_prefixes = [p.prefix for p in nb.ipam.prefixes.all() if autodiscovery_disabled_tag not in p.tags]

    # Scan networks
    hosts = scan_networks(target_prefixes)
    if not hosts:
        log.error("A critical error occurred while scanning the network, stopping")
        return

    # Filter out VMWare vCenter IPs
    vcenter_tag = nb.extras.tags.get(name='vCenter')
    vcenter_ips = [ip.address.split('/')[0] for ip in nb.ipam.ip_addresses.all() if vcenter_tag in ip.tags]
    hosts = {ip: related for ip, related in hosts.items() if ip not in vcenter_ips}

    # NetBox objects to verify, and create or update
    nb_objects = process_scan_results(hosts)
    # List of IDs of affected NetBox objects
    affected_nb_objects = defaultdict(list)
    for obj_type in NETBOX_OBJECTS_CREATION_ORDER:
        if obj_type not in nb_objects:
            continue
        log.info("Initiated sync of %s objects to NetBox", obj_type)
        for obj in nb_objects[obj_type]:
            obj_id = create_or_update_nb_obj(obj_type, obj)
            affected_nb_objects[obj_type].append(obj_id)
        log.info("Finished sync of %s objects to NetBox", obj_type)

    log.info('Initialized deletion of orphaned NetBox objects')
    autodiscovered_tag = nb.extras.tags.get(name='Autodiscovered')
    for obj_type in NETBOX_OBJECTS_DELETION_ORDER:
        log.info("Initiated deletion of %s objects from NetBox", obj_type)
        api_app = NETBOX_OBJECTS_PROPERTIES[obj_type].api_app
        all_objects = [obj for obj in getattr(getattr(nb, api_app), obj_type).all() if autodiscovered_tag in obj.tags]
        for obj in all_objects:
            if obj.id not in affected_nb_objects[obj_type]:
                log.info(
                    "Deleting '%s' object of type '%s'",
                    getattr(obj, NETBOX_OBJECTS_PROPERTIES[obj_type].key), obj_type)
                try:
                    obj.delete()
                except pynetbox.core.query.RequestError:
                    pass
        log.info("Finished deletion of %s objects from NetBox", obj_type)

    log.info('Setting primary IP addresses for devices…')
    for device_id in affected_nb_objects['devices']:
        assigned_ipv4 = list(nb.ipam.ip_addresses.filter(device_id=device_id))
        if len(assigned_ipv4) > 1:
            log.warning('More than 1 IP address found for device with ID %s', device_id)
        if len(assigned_ipv4) == 0:
            log.warning('No IP addresses found for the device with ID %s', device_id)
            continue
        nb.dcim.devices.get(id=device_id).update({'primary_ip4': assigned_ipv4[0]})


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--cleanup", action="store_true",
        help="Remove all auto discovered objects which support tagging from NetBox and exit. "
             "This is helpful if you want to start fresh or stop using this script."
    )
    args = parser.parse_args()
    if args.cleanup:
        autodiscovered_tag = nb.extras.tags.get(name='Autodiscovered')
        for obj_type in NETBOX_OBJECTS_DELETION_ORDER:
            log.info("Initiated deletion of %s objects from NetBox", obj_type)
            api_app = NETBOX_OBJECTS_PROPERTIES[obj_type].api_app
            all_objects = [obj for obj in getattr(getattr(nb, api_app), obj_type).all() if
                           autodiscovered_tag in obj.tags]
            for obj in all_objects:
                log.info(
                    "Deleting '%s' object of type '%s'",
                    getattr(obj, NETBOX_OBJECTS_PROPERTIES[obj_type].key), obj_type)
                try:
                    obj.delete()
                except pynetbox.core.query.RequestError:
                    log.warning('Failed to delete the object')
    else:
        main()
