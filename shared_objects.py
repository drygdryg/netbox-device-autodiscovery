from collections import namedtuple

import pynetbox

from configuration import config

nb = pynetbox.api(url=config['netbox']['url'], token=config['netbox']['api_token'])
Device = namedtuple('Device', ('manufacturer', 'model', 'role', 'platform'), defaults=(None, None, None, None))
NB_DEFAULT_SITE = config['netbox']['default_devices_site']
