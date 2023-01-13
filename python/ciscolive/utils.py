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
