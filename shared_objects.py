from collections import namedtuple

import pynetbox

from configuration import config
from netbox_templates import NetBoxTemplate

nb = pynetbox.api(url=config['netbox']['url'], token=config['netbox']['api_token'])
Device = namedtuple('Device', ('manufacturer', 'model', 'role', 'platform'), defaults=(None, None, None, None))
NB_DEFAULT_SITE = config['netbox']['default_devices_site']
netbox_config = config.get('netbox')
filters = netbox_config.get('filters')
default_tags = [{'name': 'auto-discovered'}]

# We're using filter as tag this is required to create objects with right filters
# IP Address doesn't support site for example
if filters:
    filter_params = {item: filters[index + 1]
                     for index, item in enumerate(filters) if index % 2 == 0}
    default_tags[0].update(filter_params)

netbox_template = NetBoxTemplate(
    default_tags=default_tags,
    default_site=NB_DEFAULT_SITE,
)
