import argparse
from collections import namedtuple, defaultdict
from typing import Optional

import pynetbox

from configuration import config
from shared_objects import NB_DEFAULT_SITE
from utils import format_slug
from logger import log

nb = pynetbox.api(url=config['netbox']['url'], token=config['netbox']['api_token'])
nb.http_session.verify = config['netbox'].get('ssl_verify', True)

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
            {'name': 'MFP', 'slug': 'mfp'},
            {'name': 'Labeling system', 'slug': 'labeling-system'},
            {'name': 'NAS', 'slug': 'nas'},
            {'name': 'Wi-Fi AP', 'slug': 'wi-fi-ap'},
            {'name': 'Wi-Fi Mesh', 'slug': 'wi-fi-mesh'},
            {'name': 'IP PBX', 'slug': 'ip-pbx'},
            {'name': 'Server', 'slug': 'server'},
            {'name': 'VoIP phone', 'slug': 'voip-phone'},
            {'name': 'Other', 'slug': 'other'}
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


def create_or_update_nb_obj(obj_type: str, obj: dict) -> Optional[int]:
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
        if obj_type in NETBOX_OBJECTS_DELETION_ORDER:  # Check whether the object supports tagging
            if 'Autodiscovered' not in (tag.name for tag in existing_nb_obj.tags):
                # Don't modify existing objects without the 'Autodiscovered' tag
                log.debug('NetBox %s object "%s" skipped because has no "Autodiscovered" tag', obj_type, obj[query_key])
                return None
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


def cleanup():
    """Remove all auto discovered objects which support tagging from NetBox"""
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


def main():
    # Check prerequisites
    verify_prerequisites()

    # List of IDs of affected NetBox objects
    affected_nb_objects = defaultdict(list)

    # Run modules and process results
    for module_name in config['data_sources']['modules']:
        log.info(f'Running module "{module_name}"…')
        module_config = config[module_name]
        module = __import__(f'modules.{module_name}')
        m = getattr(module, module_name).Module(module_config)
        # NetBox objects to verify, and create or update
        nb_objects = m.run()
        if not nb_objects:
            log.warning(f'Execution of the module "{module_name}" yielded no results')
            continue

        for obj_type in NETBOX_OBJECTS_CREATION_ORDER:
            if obj_type not in nb_objects:
                continue
            log.info("Initiated sync of %s objects to NetBox", obj_type)
            for obj in nb_objects[obj_type]:
                if obj_id := create_or_update_nb_obj(obj_type, obj):
                    affected_nb_objects[obj_type].append(obj_id)
            log.info("Finished sync of %s objects to NetBox", obj_type)
        log.info(f'Module "{module_name}" execution completed')

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
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Increase verbosity level This overrides the log level in "
             "the settings file. Intended for debugging purposes only"
    )
    args = parser.parse_args()
    if args.verbose:
        log.setLevel('DEBUG')
        log.debug("Log level has been overridden by the --verbose argument")
    if args.cleanup:
        cleanup()
    else:
        main()
