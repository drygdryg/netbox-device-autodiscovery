from typing import Optional, List

from utils import truncate, format_slug, remove_empty_fields, remove_duplicates


class NetBoxTemplate:
    """Templates for for rapid creation of NetBox objects"""
    def __init__(self, default_tags: Optional[List[dict]] = None, default_site: Optional[str] = None):
        """
        :param default_tags: Default tags for attaching to all objects with tags
        :param default_site: Default site for placing devices in it
        """
        self.default_tags = default_tags
        self.default_site = default_site

    def __merge_default_tags__(self, tags: List[dict]):
        if self.default_tags:
            return remove_duplicates(self.default_tags + tags)
        return tags

    @staticmethod
    def manufacturer(name: str, slug: Optional[str] = None) -> dict:
        """
        Template for NetBox manufacturers at /dcim/manufacturers

        :param name: Name of the manufacturer
        :param slug: Unique slug for manufacturer.
        """
        obj = {
            "name": truncate(name, max_len=50),
            "slug": slug if slug else format_slug(name)
        }
        return remove_empty_fields(obj)

    def device_type(self, manufacturer: str, model: str, slug: Optional[str] = None, part_number: Optional[str] = None,
                    tags: Optional[List[dict]] = None) -> dict:
        """
        Template for NetBox device types at /dcim/device-types/

        :param manufacturer: Name of NetBox manufacturer object
        :param model: Name of NetBox model object
        :param slug: Unique slug for manufacturer.
        :param part_number: Unique partner number for the device
        :param tags: Tags to apply to the object
        """
        obj = {
            "manufacturer": {"name": manufacturer},
            "model": truncate(model, max_len=50),
            "slug": slug if slug else format_slug(model),
            "part_number": truncate(
                part_number, max_len=50
            ) if part_number else None,
            "tags": self.__merge_default_tags__(tags) if tags else self.default_tags,
        }
        return remove_empty_fields(obj)

    def device(self, name: str, device_role: str, manufacturer: str, model: str, site: Optional[str] = None,
               platform: Optional[str] = None, serial: Optional[str] = None, asset_tag: Optional[str] = None,
               status: Optional[str] = None, tags: Optional[List[dict]] = None) -> dict:
        """
        Template for NetBox devices at /dcim/devices/

        :param name: Hostname of the device
        :param device_role: Name of device role
        :param manufacturer: Manufacturer of device type
        :param model: Model name of device type
        :param platform: Platform running on the device
        :param site: Site where the device resides
        :param serial: Serial number of the device
        :param asset_tag: Asset tag of the device
        :param status: NetBox IP address status in NB API v2.6 format
        :param tags: Tags to apply to the object
        """
        if not site:
            if not self.default_site:
                raise ValueError("You must pass the site argument or configure the default site")
            site = self.default_site
        obj = {
            "name": name,
            "role": {"name": device_role},
            "device_role": {"name": device_role},
            "device_type": {"manufacturer": {'name': manufacturer}, "model": model},
            "platform": {"name": platform} if platform else None,
            "site": {"name": site},
            "serial": truncate(serial, max_len=50) if serial else None,
            "asset_tag": truncate(asset_tag, max_len=50) if asset_tag else None,
            "status": status or "active",
            "tags": self.__merge_default_tags__(tags) if tags else self.default_tags,
            }
        return remove_empty_fields(obj)

    def device_interface(self, device: str, name: str, interface_type: Optional[str] = None,
                         enabled: Optional[bool] = None, mac_address: Optional[str] = None,
                         description: Optional[str] = None, tags: Optional[List[dict]] = None) -> dict:
        """
        Template for NetBox device interfaces at /dcim/interfaces/

        :param device: Name of parent device the interface belongs to
        :param name: Name of the physical interface
        :param interface_type: Type of the interface
        :param enabled: `True` if the interface is up else `False`
        :param mac_address: The MAC address of the interface
        :param description: Description for the interface
        :param tags: Tags to apply to the object
        """
        obj = {
            "device": {"name": device},
            "name": name,
            "type": interface_type or "other",
            "enabled": enabled,
            "mac_address": mac_address.upper() if mac_address else None,
            "description": description,
            "tags": self.__merge_default_tags__(tags) if tags else self.default_tags,
            }
        return remove_empty_fields(obj)

    def ip_address(self, address: str, device: Optional[str] = None, dns_name: Optional[str] = None,
                   interface: Optional[str] = None, status="active", tags: Optional[List[dict]] = None,
                   tenant: Optional[str] = None, description: Optional[str] = None,) -> dict:
        """
        Template for NetBox IP addresses at /ipam/ip-addresses/

        :param address: IP address
        :param device: The device which the IP and its interface are attached to
        :param dns_name: FQDN pointed to the IP address
        :param interface: Name of the parent interface IP is configured on
        :param status: `1` if active, `0` if deprecated
        :param tags: Tags to apply to the object
        :param tenant: The tenant the IP address belongs to
        :param description: A description of the IP address purpose
        """
        obj = {
            "address": address,
            "description": description,
            "dns_name": dns_name,
            "status": status,
            "tags": self.__merge_default_tags__(tags) if tags else self.default_tags,
            "tenant": tenant,
            }
        if interface and device:
            obj["assigned_object_type"] = "dcim.interface"
            obj["assigned_object"] = {"name": interface, "device": {"name": device}}
        return remove_empty_fields(obj)

    @staticmethod
    def platform(name: str, slug: Optional[str] = None, manufacturer: Optional[str] = None,
                 description: Optional[str] = None) -> dict:
        """
        Template for NetBox platforms at /dcim/platforms/

        :param name: Name of NetBox platform object
        :param slug: Unique slug for platform
        :param manufacturer: Name of the manufacturer
        :param description: Description for platform
        """
        obj = {
            "name": name,
            "slug": slug if slug else format_slug(name),
            "manufacturer": {"name": manufacturer} if manufacturer else None,
            "description": description,
        }
        return remove_empty_fields(obj)
