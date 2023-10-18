import _ncs.maapi as _maapi  # type: ignore
import requests
from typing import Tuple


def get_platform(root, device):
    """
    Return the platform name for a given device ref.
    """

    return root.devices.device[device.device].platform.name.lower()


def get_peer_id(id):
    """
    Get a peer ID given the local ID number.
    """

    if int(id) == 1:
        return 2

    return 1


def get_switch_index(did, sid):
    """
    Get the switch's flattened list index given the DC ID and the switch ID.
    """

    return int(sid) - 1 + (int(did) * 2 - 2)


def get_switch_octet(did, sid):
    """
    Get the IP octet that represents the switch.
    """

    return 253 - ((6 - get_switch_index(did, sid)))


def construct_v4_address(dc, vlan, ip_info):
    """
    Construct an IPv4 address for an SVI.
    """

    octets = str(ip_info.v4_network).split(".")
    if int(ip_info.vlan_octet_position) > -1:
        if ip_info.vlan_octet_position == ip_info.dc_octet_position:
            raise ValueError("vlan-octet-position cannot be the same as dc-octet-position")

        octets[int(ip_info.vlan_octet_position) - 1] = str(vlan.id)

    if int(ip_info.dc_octet_position) > -1:
        if vlan.cross_dc:
            octets[int(ip_info.dc_octet_position) - 1] = str(ip_info.cross_dc_octet)
        else:
            octets[int(ip_info.dc_octet_position) - 1] = str(list(ip_info.dc_octet)[dc.id - 1])

    return ".".join(octets)


def construct_v6_address(dc, vlan, ip_info):
    """
    Construct an IPv6 address for an SVI.
    """

    hextets = str(ip_info.v6_network).split(":")
    hextet = 0
    if int(ip_info.vlan_octet_position) > -1:
        if ip_info.vlan_octet_position == ip_info.dc_octet_position:
            raise ValueError("vlan-octet-position cannot be the same as dc-octet-position")

        if int(ip_info.vlan_octet_position) == 2:
            hextet |= int(vlan.id) << 8
        else:
            hextet |= int(vlan.id)

    if int(ip_info.dc_octet_position) > -1:
        octet = int(ip_info.cross_dc_octet)
        if not vlan.cross_dc:
            octet = int(list(ip_info.dc_octet)[dc.id - 1])

        if int(ip_info.dc_octet_position) == 2:
            hextet |= octet << 8
        else:
            hextet |= octet

    hextets[-2] = format(hextet, "x")
    # Re-add the last element.
    hextets.append("")

    return ":".join(hextets)


def get_users_groups(trans, uinfo):
    # Get the maapi socket
    s = trans.maapi.msock
    auth = _maapi.get_authorization_info(s, uinfo.usid)
    return list(auth.groups)


def form_login(url: str, request: dict, method: str = "POST", **kwargs) -> Tuple[requests.Session, requests.Response]:
    """Login to a web-based form and return the session object."""
    s = requests.Session()
    response = s.request(method, url, data=request, **kwargs)
    response.raise_for_status()

    return (s, response)
