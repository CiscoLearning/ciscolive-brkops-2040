import ncs  # type: ignore
from ncs.dp import Action  # type: ignore
from _ncs import decrypt  # type: ignore
import pynetbox
import json
from .utils import get_users_groups

# Constants
# XXX: Maybe these should be in the model.
DC_TENANT = "dc-infrastructure"
CROSS_DC_VLAN_GROUP = "Cross-DC VLANs"
DC1_VLAN_GROUP = "DC1 VLANs"
DC2_VLAN_GROUP = "DC2 VLANs"


class CiscoLiveNetboxServerAction(Action):
    @Action.action
    def cb_action(self, uinfo, name, kp, action_input, action_output, trans):
        self.log.info("NetboxServerAction: ", name)
        service = ncs.maagic.get_node(trans, kp)
        root = ncs.maagic.get_root(trans)
        trans.maapi.install_crypto_keys()

        if name == "verify-status":
            self.verify_status(service, root, action_output)

    def verify_status(self, service, root, action_output):
        """Perform a status check that NetBox is reachable."""
        nb = pynetbox.api(service.url, token=decrypt(service.api_token))
        try:
            status = nb.status()
        except Exception as e:
            action_output.success = False
            action_output.output = f"Error connecting to NetBox server at URL {service.url}: {e}"
            return

        action_output.success = True
        action_output.output = (
            f"NetBox Version: {status['netbox-version']}, Python Version: {status['python-version']}, "
            f"Plugins: {status['plugins']}, Workers Running: {status['rq-workers-running']}"
        )


# class ComplexEncoder(json.JSONEncoder):
#     def default(self, obj):
#         if isinstance(obj, pynetbox.models.ipam.Prefixes):
#             return str(obj)

#         return json.JSONEncoder.default(self, obj)


class CiscoLiveNetboxVlanAction(Action):
    @staticmethod
    def _get_new_vlans(nb, nb_vlans, service):
        global CROSS_DC_VLAN_GROUP, DC1_VLAN_GROUP
        new_vlans = {}

        for nbv in nb_vlans:
            vid = nbv.vid
            routed = nbv.prefix_count > 0
            # XXX: Should this be metadata in NetBox?
            dhcp = False
            category = nbv.custom_fields["category"]
            cross_dc = nbv.group.name == CROSS_DC_VLAN_GROUP
            ipv4_acl = ""
            ipv6_acl = ""
            if nbv.custom_fields["ipv4acl"]:
                ipv4_acl = nbv.custom_fields["ipv4acl"]

            if nbv.custom_fields["ipv6acl"]:
                ipv6_acl = nbv.custom_fields["ipv6acl"]

            if nbv.custom_fields["attendeeacl"]:
                if ipv6_acl != "" or ipv4_acl != "":
                    raise ValueError(f"VLAN {vid} ({nbv.name}): Only one of a named ACL or use of the Attendee ACL can be chosen.")

                ipv4_acl = service.security.v4_attendee_acl
                ipv6_acl = service.security.v6_attendee_acl

            native = nbv.custom_fields["native"]

            if vid not in new_vlans:
                new_vlans[vid] = {
                    "id": nbv.id,
                    "name": nbv.name,
                    "routed": routed,
                    "dhcp": dhcp,
                    "category": category,
                    "cross-dc": cross_dc,
                    "native": native,
                    "prefixes": [],
                    "ipv4-acl": ipv4_acl,
                    "ipv6-acl": ipv6_acl,
                }

            if routed:
                prefixes = list(nb.ipam.prefixes.filter(vlan_id=nbv.id))
                # This seems a bit weird.  Prefixes will always be either a
                # 1, 2 or 4 element list.  When dealing with DC2, make sure its
                # prefixes are at the end of the list.
                if cross_dc:
                    # Only in this case can prefixes just have 1 element.
                    new_vlans[vid]["prefixes"] = prefixes
                elif nbv.group.name == DC1_VLAN_GROUP:
                    for i, prefix in enumerate(prefixes):
                        new_vlans[vid]["prefixes"].insert(i, prefix)
                else:
                    for i, prefix in enumerate(prefixes):
                        new_vlans[vid]["prefixes"].insert(i + 2, prefix)

        return new_vlans

    @Action.action
    def cb_action(self, uinfo, name, kp, action_input, action_output, trans):
        global DC_TENANT
        self.log.info("NetboxVlanAction:", name)
        service = ncs.maagic.get_node(trans, kp)
        root = ncs.maagic.get_root(trans)
        trans.maapi.install_crypto_keys()
        netbox_server = root.netbox_server[service.netbox_server]

        ugroups = get_users_groups(trans, uinfo)
        self.log.info(f"User groups are {ugroups}")

        nb = pynetbox.api(netbox_server.url, token=decrypt(netbox_server.api_token))

        try:
            # Get the list of infrastructure VLANS.
            nb_vlans = list(nb.ipam.vlans.filter(tenant=DC_TENANT))
            nb_ids = [nbv.id for nbv in nb_vlans]
        except Exception as e:
            action_output.success = False
            action_output.output = f"Failed to get list of infrastructure VLANS from NetBox: {e}"
            return

        # Get the list of current VLANs from this instance of CiscoLive.
        cl_vlans = list(service.vlan)

        # Iterate through the VLANs in NetBox and add them to NSO.
        # We move this out from the transaction as this potentially calls out
        # to NetBox again.
        try:
            new_vlans = CiscoLiveNetboxVlanAction._get_new_vlans(nb, nb_vlans, service)
        except Exception as e:
            action_output.success = False
            action_output.output = str(e)
            return

        # vlan_message = [""]
        dry_run = {}

        with ncs.maapi.Maapi() as m:
            with ncs.maapi.Session(m, user=uinfo.username, context=name, groups=ugroups):
                with m.start_write_trans() as t:
                    # Get a writeable service instance
                    writeable_service = ncs.maagic.get_node(t, service._path)
                    template = ncs.template.Template(writeable_service)

                    # Do a pass through all VLANs with a netbox-id.
                    # If the VLAN doesn't exist in NetBox, remove it.
                    # vlan_message.append("# VLANs to Delete:")
                    for clv in cl_vlans:
                        if clv.netbox_id:
                            if clv.netbox_id not in nb_ids:
                                # vlan_message.append(f" {clv.id} ({clv.name})")

                                vars = ncs.template.Variables()
                                vars.add("LOCATION", service.location)
                                vars.add("YEAR", service.year)
                                vars.add("VLAN_ID", clv.id)

                                self.log.info(f"Removing VLAN {clv.id} ({clv.name}) as it is no longer in NetBox.")
                                template.apply("ciscolive-vlan-remove", vars)

                    # vlan_message.append("")
                    # vlan_message.append("# VLANs to Add/Modify:")

                    for vid, vlan in new_vlans.items():
                        # vlan_message.append(json.dumps({vid: vlan}, indent=2, cls=ComplexEncoder) + ",")

                        vars = ncs.template.Variables()
                        vars.add("LOCATION", service.location)
                        vars.add("YEAR", service.year)
                        vars.add("VLAN_ID", vid)
                        vars.add("VLAN_NAME", vlan["name"])
                        vars.add("ROUTED", vlan["routed"])
                        vars.add("CROSS_DC", vlan["cross-dc"])
                        vars.add("NATIVE", vlan["native"])
                        vars.add("DHCP", vlan["dhcp"])
                        vars.add("CATEGORY", vlan["category"])
                        vars.add("NETBOX_ID", vlan["id"])

                        if vlan["routed"]:
                            if vlan["cross-dc"]:
                                vars.add("DC1_IPV4_PREFIX", "")
                                vars.add("DC1_IPV6_PREFIX", "")
                                vars.add("DC2_IPV4_PREFIX", "")
                                vars.add("DC2_IPV6_PREFIX", "")
                                if len(vlan["prefixes"]) == 2:
                                    # This has a custom IPv6 prefix
                                    for prefix in vlan["prefixes"]:
                                        if prefix.family.value == 4:
                                            vars.add("IPV4_PREFIX", prefix.prefix)
                                        else:
                                            vars.add("IPV6_PREFIX", prefix.prefix)
                                else:
                                    vars.add("IPV4_PREFIX", vlan["prefixes"][0].prefix)
                                    vars.add("IPV6_PREFIX", "")
                            else:
                                vars.add("IPV4_PREFIX", "")
                                vars.add("IPV6_PREFIX", "")
                                if len(vlan["prefixes"]) == 4:
                                    # This has a custom IPv6 prefix per DC
                                    for prefix in vlan["prefixes"][0:2]:
                                        if prefix.family.value == 4:
                                            vars.add("DC1_IPV4_PREFIX", prefix.prefix)
                                        else:
                                            vars.add("DC1_IPV6_PREFIX", prefix.prefix)

                                    for prefix in vlan["prefixes"][2:4]:
                                        if prefix.family.value == 4:
                                            vars.add("DC2_IPV4_PREFIX", prefix.prefix)
                                        else:
                                            vars.add("DC2_IPV6_PREFIX", prefix.prefix)
                                else:
                                    # We have already ensured DC2 comes after DC1 using the insert magic above.
                                    vars.add("DC1_IPV4_PREFIX", vlan["prefixes"][0].prefix)
                                    vars.add("DC2_IPV4_PREFIX", vlan["prefixes"][1].prefix)
                                    vars.add("DC1_IPV6_PREFIX", "")
                                    vars.add("DC2_IPV6_PREFIX", "")

                            vars.add("V4_ACL", vlan["ipv4-acl"])
                            vars.add("V6_ACL", vlan["ipv6-acl"])
                        else:
                            vars.add("DC1_IPV4_PREFIX", "")
                            vars.add("DC1_IPV6_PREFIX", "")
                            vars.add("DC2_IPV4_PREFIX", "")
                            vars.add("DC2_IPV6_PREFIX", "")
                            vars.add("IPV4_PREFIX", "")
                            vars.add("IPV6_PREFIX", "")
                            vars.add("V4_ACL", "")
                            vars.add("V6_ACL", "")

                        self.log.info(f"Applying template ciscolive-vlan-add with vars {dict(vars)}")
                        template.apply("ciscolive-vlan-add", vars)

                    if action_input.commit:
                        t.apply()
                    else:
                        cp = ncs.maapi.CommitParams()
                        # Native worked, but CLI is a bit nicer since it includes the service itself.
                        cp.dry_run_cli()
                        dry_run = t.apply_params(True, cp)

        if action_input.commit:
            action_output.output = "Commit done."
        else:
            action_output.output = json.dumps(dry_run, indent=2).replace("\\n", "\n")

        action_output.success = True
