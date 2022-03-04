from collections import namedtuple

import pynetbox

from configuration import config
from netbox_templates import NetBoxTemplate

nb = pynetbox.api(url=config['netbox']['url'], token=config['netbox']['api_token'])
nb.http_session.verify = config['netbox'].get('ssl_verify', True)

Device = namedtuple('Device', ('manufacturer', 'model', 'role', 'platform'), defaults=(None, None, None, None))
NB_DEFAULT_SITE = config['netbox']['default_devices_site']
netbox_template = NetBoxTemplate(
    default_tags=[{
        'name': 'Autodiscovered'
    }],
    default_site=NB_DEFAULT_SITE
)
