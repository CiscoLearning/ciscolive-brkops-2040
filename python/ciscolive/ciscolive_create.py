import ncs  # type:  ignore
import ipaddress
import re
from ncs.application import Service  # type:  ignore
from _ncs import decrypt  # type:  ignore
from .utils import get_platform, get_peer_id, get_switch_index, get_switch_octet

MGMT_INTF = "loopback0"


class CiscoLiveServiceCreate(Service):
    @Service.create
    def cb_create(self, tctx, root, service, proplist):
        self.log.info("Service create(service=", service._path, ")")

        # Setup decryption keys.
        trans = ncs.maagic.get_trans(root)
        trans.maapi.install_crypto_keys()

        self.service = service
        self.root = root
        self.tctx = tctx

        for dc in service.data_center:
            # Create DC switches.
            for switch in dc.switch:
                self.setup_dc_switch(dc, switch)
                self.setup_dns(dc, switch)
                self.setup_ospf(dc, switch)
                self.setup_mgmt_intf(dc, switch)
                self.setup_static_routing(dc, switch)
                self.setup_mgmt_acl(dc, switch)
                self.setup_switch_l2(dc, switch)
                self.setup_hsrp_key(dc, switch)
                if service.pim.rp and service.pim != "":
                    self.setup_pim(dc, switch)
                self.setup_netflow(dc, switch)

                self.setup_svis(dc, switch)
                self.setup_port_channels(dc, switch)
                self.setup_ethernet(dc, switch)
                self.setup_aaa(dc, switch)
                self.setup_local_users(dc, switch)
                self.setup_ntp(dc, switch)
                self.setup_snmp(dc, switch)
                self.setup_logging(dc, switch)

            # Configure DC FIs.
            for fi in dc.fabric_interconnect:
                self.setup_dns(dc, fi)
                self.setup_ntp(dc, fi)
                self.setup_snmp(dc, fi)
                self.setup_logging(dc, fi)
                self.setup_fi_vlan(dc, fi)
                self.setup_fi_vnic_templ(dc, fi)

            if service.vcenter:
                for vcenter in service.vcenter:
                    self.setup_vcenter_vlans(dc, vcenter)

    def setup_dc_switch(self, dc, switch):
        """
        Configure base parameters on each DC switch.
        """

        self.log.info(f"Calling setup_dc_switch for DC {dc.id} with switch ID {switch.id}, name {switch.device}")

        # Set a spanning-tree priority based on switch and DC IDs.
        stp_prio = get_switch_index(dc.id, switch.id) * 4096

        # Setup vPC parameters.
        vpc_id = int(dc.id)
        vpc_self = switch.keepalive_ip
        vpc_peer = None
        vpc_peer_name = None
        for peer_sw in dc.switch:
            if peer_sw.id != switch.id:
                vpc_peer = peer_sw.keepalive_ip
                vpc_peer_name = peer_sw.device
                break

        vpc_keep_intf = self.service.vpc_peer.keepalive_interface
        vpc_peer_pc = self.service.vpc_peer.peer_port_channel

        base_vars = ncs.template.Variables()
        base_templ = ncs.template.Template(self.service)
        member_templ = ncs.template.Template(self.service)

        if vpc_self == vpc_peer:
            raise ValueError("vPC keepalive addresses cannot be the same between peers.")

        vpc_local_net = ipaddress.ip_network(f"{vpc_self}/30", strict=False)
        vpc_peer_net = ipaddress.ip_network(f"{vpc_peer}/30", strict=False)

        if vpc_local_net != vpc_peer_net:
            raise ValueError(f"vPC keepalive IP {vpc_self} is not in the same /30 network as peer {vpc_peer}.")

        base_vars.add("DEVICE", switch.device)
        base_vars.add("SWITCH_ID", switch.id)
        base_vars.add("DC_ID", dc.id)
        base_vars.add("STP_PRIO", stp_prio)
        base_vars.add("VPC_ID", vpc_id)
        base_vars.add("VPC_LOCAL_IP", vpc_self)
        base_vars.add("VPC_PEER_IP", vpc_peer)
        base_vars.add("VPC_PEER_SW", vpc_peer_name)
        base_vars.add("VPC_PORT_CHANNEL", vpc_peer_pc)
        base_vars.add("VPC_KEEP_INTF", vpc_keep_intf)
        base_vars.add("YEAR", self.service.year)
        base_vars.add("CONTACT", self.service.contact)

        self.log.info(f"Applying template switch-base-cfg with vars {dict(base_vars)}")
        base_templ.apply("switch-base-cfg", base_vars)

        for member in self.service.vpc_peer.member_interface:
            base_vars.add("MEMBER_INTF", member)
            self.log.info(f"Applying template vpc-member-cfg for interface {member}")
            member_templ.apply("vpc-member-cfg", base_vars)

    def setup_switch_l2(self, dc, switch):
        """
        Configure L2 VLAN parameters for a DC switch.
        """

        self.log.info(f"Calling setup_switch_l2 for DC {dc.id} with switch ID {switch.id}, name {switch.device}")

        l2_vars = ncs.template.Variables()
        l2_templ = ncs.template.Template(self.service)

        l2_vars.add("DEVICE", switch.device)

        for vlan in self.service.vlan:
            l2_vars.add("VLAN_ID", vlan.id)
            l2_vars.add("VLAN_NAME", vlan.name.format(dc=dc.id, peer_dc=get_peer_id(dc.id)))

            self.log.info(f"Applying template l2-vlan-cfg with vars {dict(l2_vars)}")
            l2_templ.apply("l2-vlan-cfg", l2_vars)

    def setup_pim(self, dc, switch):
        """
        Configure PIM settings on a DC switch.
        """

        self.log.info(f"Calling setup_pim for DC {dc.id} with switch ID {switch.id}, name {switch.device}")

        pim_vars = ncs.template.Variables()
        pim_templ = ncs.template.Template(self.service)

        pim_vars.add("DEVICE", switch.device)
        pim_vars.add("RP_ADDRESS", self.service.pim.rp)
        pim_vars.add("SSM_RANGE", self.service.pim.ssm_range)
        pim_vars.add("PIM_SOURCE", MGMT_INTF)

        self.log.info(f"Applying template pim-cfg with vars {dict(pim_vars)}")
        pim_templ.apply("pim-cfg", pim_vars)

    def setup_netflow(self, dc, switch):
        """
        Configure NetFlow settings on a DC switch.
        """

        self.log.info(f"Calling setup_netflow for DC {dc.id} with switch ID {switch.id}, name {switch.device}")

        netflow_vars = ncs.template.Variables()
        netflow_templ = ncs.template.Template(self.service)

        netflow_vars.add("DEVICE", switch.device)
        netflow_vars.add("EXPORTER", self.service.netflow.exporter)
        netflow_vars.add("EXPORT_INTF", MGMT_INTF)

        self.log.info(f"Applying template nx-netflow-base-cfg with vars {dict(netflow_vars)}")
        netflow_templ.apply("nx-netflow-base-cfg", netflow_vars)

    def setup_hsrp_key(self, dc, switch):
        """
        Configure HSRP key-chain.
        """

        self.log.info(f"Calling setup_hsrp_key for DC {dc.id} with switch ID {switch.id}, name {switch.device}")

        hsrp_vars = ncs.template.Variables()
        hsrp_templ = ncs.template.Template(self.service)

        hsrp_vars.add("DEVICE", switch.device)
        hsrp_vars.add("HSRP_KEY", decrypt(self.service.security.hsrp_key))

        self.log.info("Applying template hsrp-key-cfg")
        hsrp_templ.apply("hsrp-key-cfg", hsrp_vars)

    def setup_mgmt_intf(self, dc, switch):
        """
        Setup the mgmt interface, which is loopback0.
        """

        self.log.info(f"Calling setup_mgmt_intf for DC {dc.id} with switch ID {switch.id}, name {switch.device}")

        mintf_vars = ncs.template.Variables()
        mintf_templ = ncs.template.Template(self.service)

        mintf_vars.add("DEVICE", switch.device)

        v4_subnet = ipaddress.ip_network(self.service.management.interface.v4_subnet)
        if v4_subnet.prefixlen != 32:
            raise ValueError("Management interface v4-subnet prefixlen must be /32.")

        v4_addr = list(v4_subnet.hosts())[0]
        if v4_addr.packed[-1] != 0:
            raise ValueError("Management interface v4-subnet must end with 0.")

        v4_addr += get_switch_octet(dc.id, switch.id)

        mintf_vars.add("V4_ADDR", f"{v4_addr}/{v4_subnet.prefixlen}")

        v6_prefix = ipaddress.ip_network(self.service.management.interface.v6_prefix)
        if v6_prefix.prefixlen != 128:
            raise ValueError("Management interface v6-prefix prefixlen must be /128.")

        v6_addr = list(v6_prefix.hosts())[0]
        if v6_addr.packed[-1] != 0:
            raise ValueError("Management interface v6-prefix must end with a 0 octet.")

        v6_addr += get_switch_octet(dc.id, switch.id)

        mintf_vars.add("V6_ADDR", f"{v6_addr}/{v6_prefix.prefixlen}")

        self.log.info(f"Applying template nx-mgmt-intf with vars {dict(mintf_vars)}")
        mintf_templ.apply("nx-mgmt-intf", mintf_vars)

    def setup_svis(self, dc, switch):
        """
        Setup SVIs for all routed VLANs.
        """

        self.log.info(f"Calling setup_svis for DC {dc.id} with switch ID {switch.id}, name {switch.device}")

        svi_vars = ncs.template.Variables()
        svi_templ = ncs.template.Template(self.service)

        svi_vars.add("DEVICE", switch.device)

        for vlan in self.service.vlan:
            if not vlan.routed:
                continue

            self.log.info(f"Building variables for VLAN {vlan.id}")

            svi_vars.add("VLAN_ID", vlan.id)

            # Determine HSRP priority based on switch ID and DC ID
            svi_vars.add("HSRP_PRIORITY", 105 - get_switch_index(dc.id, switch.id))

            svi_vars.add("DESCRIPTION", vlan.name.format(dc=dc.id, peer_dc=get_peer_id(dc.id)))
            svi_vars.add("CATEGORY", vlan.category)

            # Add IPv4 parameters
            if vlan.cross_dc and vlan.category != "peer":
                ipv4_prefix = ipaddress.ip_network(vlan.ip.prefix)
            else:
                dc_prefix = next(d for d in vlan.ip.data_center if d["id"] == dc.id)
                ipv4_prefix = ipaddress.ip_network(dc_prefix.prefix)

            v4_vip = list(ipv4_prefix.hosts())[-1]
            svi_vars.add("HSRP_V4_VIP", v4_vip)
            svi_vars.add("HSRP_V4_VIP", v4_vip)
            # Essentially we start at the second to last host address and subtract so that DC 1 switch 1 gets the smallest host address.
            v4_addr = list(ipv4_prefix.hosts())[-2 - ((6 - get_switch_index(dc.id, switch.id)))]
            svi_vars.add(
                "SVI_V4",
                f"{v4_addr}/{ipv4_prefix.prefixlen}",
            )

            if vlan.ip.access_group and vlan.ip.access_group != "":
                svi_vars.add("ACCESS_GROUP", vlan.ip.access_group)
            else:
                svi_vars.add("ACCESS_GROUP", "")

            # Add IPv6 parameters
            if ("ciscolive:prefix" in vlan.ipv6 and vlan.ipv6.prefix and vlan.ipv6.prefix != "") or (
                "ciscolive:data-center" in vlan.ipv6 and not vlan.ipv6.link_local_only
            ):
                if vlan.cross_dc and vlan.category != "peer":
                    ipv6_prefix = ipaddress.ip_network(vlan.ipv6.prefix)
                else:
                    dc_prefix = next(d for d in vlan.ipv6.data_center if d["id"] == dc.id)
                    ipv6_prefix = ipaddress.ip_network(dc_prefix.prefix)

                vip_octet = format(int(str(v4_vip).split(".")[-1]), "x")
                v6_octet = format(int(str(v4_addr).split(".")[-1]), "x")
                svi_vars.add(
                    "HSRP_V6_VIP",
                    f"{ipv6_prefix.network_address}{vip_octet}",
                )
                svi_vars.add(
                    "SVI_V6",
                    f"{ipv6_prefix.network_address}{v6_octet}/{ipv6_prefix.prefixlen}",
                )
                svi_vars.add("LINK_LOCAL", "False")
                if vlan.ipv6.traffic_filter and vlan.ipv6.traffic_filter != "":
                    svi_vars.add("TRAFFIC_FILTER", vlan.ipv6.traffic_filter)
                else:
                    svi_vars.add("TRAFFIC_FILTER", "")

            elif vlan.ipv6.link_local_only:
                svi_vars.add("HSRP_V6_VIP", "")
                svi_vars.add("SVI_V6", "")
                svi_vars.add("TRAFFIC_FILTER", "")
                svi_vars.add("LINK_LOCAL", "True")
            else:
                svi_vars.add("HSRP_V6_VIP", "")
                svi_vars.add("SVI_V6", "")
                svi_vars.add("TRAFFIC_FILTER", "")
                svi_vars.add("LINK_LOCAL", "False")

            if vlan.category == "peer":
                svi_vars.add("BANDWIDTH", self.service.bandwidth)
            else:
                svi_vars.add("BANDWIDTH", "")

            self.log.info(f"Applying template svi-base-cfg with vars {dict(svi_vars)}")
            svi_templ.apply("svi-base-cfg", svi_vars)

            if vlan.dhcp:
                self.setup_dhcp_relays(dc, switch, vlan)
                self.setup_nd_dns_servers(dc, switch, vlan)
                self.setup_nd_dns_search(dc, switch, vlan)

    def setup_nd_dns_servers(self, dc, switch, vlan):
        """
        Configure DNS servers for IPv6 ND.
        """

        self.log.info(f"Calling setup_nd_dns_servers for DC {dc.id} with switch ID {switch.id}, name {switch.device} and VLAN {vlan.id}")

        dns_vars = ncs.template.Variables()
        dns_templ = ncs.template.Template(self.service)

        dns_vars.add("DEVICE", switch.device)
        dns_vars.add("VLAN_ID", vlan.id)

        for idx, server in enumerate(self.service.dns.v6_server):
            dns_vars.add("SERVER", server)
            dns_vars.add("SEQ", idx)

            self.log.info(f"Applying template svi-nd-dns-server-cfg with vars {dict(dns_vars)}")
            dns_templ.apply("svi-nd-dns-server-cfg", dns_vars)

    def setup_nd_dns_search(self, dc, switch, vlan):
        """
        Configure DNS search for IPv6 ND.
        """

        self.log.info(f"Calling setup_nd_dns_search for DC {dc.id} with switch ID {switch.id}, name {switch.device} and VLAN {vlan.id}")

        dns_vars = ncs.template.Variables()
        dns_templ = ncs.template.Template(self.service)

        dns_vars.add("DEVICE", switch.device)
        dns_vars.add("VLAN_ID", vlan.id)

        dns_vars.add("DOMAIN", self.service.dns.domain)

        self.log.info(f"Applying template svi-nd-dns-search-cfg with vars {dict(dns_vars)}")
        dns_templ.apply("svi-nd-dns-search-cfg", dns_vars)

    def setup_dhcp_relays(self, dc, switch, vlan):
        """
        Configure DHCP relay addresses.
        """

        self.log.info(f"Calling setup_dhcp_relays for DC {dc.id} with switch ID {switch.id}, name {switch.device} and VLAN {vlan.id}")

        dhcp_vars = ncs.template.Variables()
        dhcp_templ = ncs.template.Template(self.service)

        dhcp_vars.add("DEVICE", switch.device)
        dhcp_vars.add("VLAN_ID", vlan.id)

        for relay in self.service.dhcp.relay:
            dhcp_vars.add("RELAY_ADDR", relay)
            self.log.info(f"Applying template svi-dhcp-relay-cfg for relay {relay}")
            dhcp_templ.apply("svi-dhcp-relay-cfg", dhcp_vars)

    def setup_port_channels(self, dc, switch):
        """
        Configure port-channels on each switch.
        """

        self.log.info(f"Calling setup_port_channels for DC {dc.id} with switch ID {switch.id}, name {switch.device}")

        pc_vars = ncs.template.Variables()
        pc_templ = ncs.template.Template(self.service)

        pc_vars.add("DEVICE", switch.device)

        for intf in self.service.interface.port_channel:
            pc_vars.add("PC_NAME", intf.name)
            if "ciscolive:description" in intf and intf.description and intf["ciscolive:description"] != "":
                # Single description for this interface for all switches.
                pc_vars.add(
                    "DESCRIPTION",
                    str(intf.description).format(
                        dc=dc.id, switch=switch.id, peer_dc=get_peer_id(dc.id), peer_switch=get_peer_id(switch.id)
                    ),
                )
            elif "ciscolive:description-list" in intf and intf.description_list:
                # Unique descriptions for this interface for each switch.
                if len(list(intf.description_list)) == 2:
                    pc_vars.add("DESCRIPTION", list(intf.description_list)[int(dc.id) - 1])
                else:
                    pc_vars.add("DESCRIPTION", list(intf.description_list)[get_switch_index(dc.id, switch.id)])
            else:
                pc_vars.add("DESCRIPTION", "")

            if intf.mode == "trunk" or intf.mode == "cross-dc-link":
                pc_vars.add("MODE", "trunk")
                pc_vars.add("ACCESS_VLAN", "")
            else:
                pc_vars.add("MODE", "access")
                pc_vars.add("ACCESS_VLAN", intf.vlan)

            # pc_vars.add("CATEGORY", intf.category)
            # TODO: File bug for "ipv6 nd raguard"

            self.log.info(f"Applying template port-channel-base-cfg with vars {dict(pc_vars)}")
            pc_templ.apply("port-channel-base-cfg", pc_vars)

            if intf.mode == "trunk" or intf.mode == "cross-dc-link":
                self.setup_port_channel_allowed_vlans(dc, switch, intf)

            # Setup member-interfaces.
            for member in intf.member_interface:
                self.setup_port_channel_member(dc, switch, intf, member)

    def setup_port_channel_allowed_vlans(self, dc, switch, intf):
        """
        Configure allowed VLANs per port-channel.
        """

        self.log.info(
            f"Calling setup_port_channel_allowed_vlans for DC {dc.id} with switch ID {switch.id}, name {switch.device},"
            f"port-channel {intf.name}"
        )

        allowed_vlan_vars = ncs.template.Variables()
        allowed_vlan_templ = ncs.template.Template(self.service)

        allowed_vlan_vars.add("DEVICE", switch.device)
        allowed_vlan_vars.add("PC_NAME", intf.name)

        allowed_vlans = []
        if not intf.allowed_vlan or len(intf.allowed_vlan) == 0:
            # Determine allowed VLANs based on category or whether they are cross-dc
            for vlan in self.service.vlan:
                if intf.mode == "trunk":
                    if vlan.category in intf.category:
                        allowed_vlans.append(vlan.id)
                else:
                    if vlan.cross_dc:
                        allowed_vlans.append(vlan.id)
        else:
            allowed_vlans = intf.allowed_vlan

        for vlan in allowed_vlans:
            allowed_vlan_vars.add("ALLOWED_VLAN", vlan)
            self.log.info(f"Applying template port-channel-allowed-vlan-cfg with VLAN {vlan}")
            allowed_vlan_templ.apply("port-channel-allowed-vlan-cfg", allowed_vlan_vars)

    def setup_port_channel_member(self, dc, switch, port_channel, intf):
        """
        Configure member interfaces in the port-channel.
        """

        self.log.info(
            f"Calling setup_port_channel_allowed_vlans for DC {dc.id} with switch ID {switch.id}, name {switch.device},"
            f"port-channel {port_channel.name}, member {intf.name}"
        )

        member_vars = ncs.template.Variables()
        member_templ = ncs.template.Template(self.service)

        member_vars.add("DEVICE", switch.device)
        member_vars.add("PC_NAME", port_channel.name)
        member_vars.add("INTF_NAME", intf.name)
        member_vars.add("MODE", port_channel.mode)
        member_vars.add("PROTOCOL", port_channel.protocol)

        # This will actually fail once an interface becomes "owned" by the service.
        # This will fail later on when an invalid interface is configured, so this check isn't critical.
        # if intf.name not in self.root.devices.device[switch.device].config.interface.Ethernet:
        #     raise ValueError(f"Member interface {intf.name} is not a valid Ethernet interface.")

        if "ciscolive:description" in intf and intf.description and intf["ciscolive:description"] != "":
            # This member has the same description on all switches.
            member_vars.add(
                "DESCRIPTION",
                str(intf.description).format(dc=dc.id, switch=switch.id, peer_dc=get_peer_id(dc.id), peer_switch=get_peer_id(switch.id)),
            )
        elif "ciscolive:description-list" in intf and intf.description_list:
            # The member on each switch gets its own interface.
            if len(list(intf.description_list)) == 2:
                member_vars.add("DESCRIPTION", list(intf.description_list)[int(dc.id) - 1])
            else:
                member_vars.add("DESCRIPTION", list(intf.description_list)[get_switch_index(dc.id, switch.id)])
        else:
            member_vars.add("DESCRIPTION", "")

        self.log.info(f"Applying template port-channel-member-intf-cfg with vars {dict(member_vars)}")
        member_templ.apply("port-channel-member-intf-cfg", member_vars)

    def setup_ethernet(self, dc, switch):
        """
        Configure Ethernet ports on each switch.
        """

        self.log.info(f"Calling setup_switch_ethernet for DC {dc.id} with switch ID {switch.id}, name {switch.device}")

        ethernet_vars = ncs.template.Variables()
        ethernet_templ = ncs.template.Template(self.service)

        ethernet_vars.add("DEVICE", switch.device)

        sindex = get_switch_index(dc.id, switch.id)

        for intf in self.service.interface.Ethernet:
            # This will fail once the interface actually becomes owned by the service.
            # This will fail later on when an invalid interface is configured, so this check isn't critical.
            # if intf.name not in self.root.devices.device[switch.device].config.interface.Ethernet:
            #     raise ValueError(f"Interface {intf.name} is not a valid Ethernet interface for {switch.device}.")

            ethernet_vars.add("INTF_NAME", intf.name)
            if "ciscolive:description" in intf and intf.description and intf["ciscolive:description"] != "":
                # This port gets the same description on all switches.
                ethernet_vars.add(
                    "DESCRIPTION",
                    str(intf.description).format(
                        dc=dc.id, switch=switch.id, peer_dc=get_peer_id(dc.id), peer_switch=get_peer_id(switch.id)
                    ),
                )
            elif "ciscolive:description-list" in intf and intf.description_list:
                # This port gets a unique description on each switch.
                if len(list(intf.description_list)) == 2:
                    ethernet_vars.add("DESCRIPTION", list(intf.description_list)[int(dc.id) - 1])
                else:
                    ethernet_vars.add("DESCRIPTION", list(intf.description_list)[sindex])
            else:
                ethernet_vars.add("DESCRIPTION", "")

            if intf.speed and intf.speed != "":
                ethernet_vars.add("SPEED", intf.speed)
            else:
                ethernet_vars.add("SPEED", "")

            ethernet_vars.add("MODE", intf.mode)

            if intf.mode == "access":
                ethernet_vars.add("VLAN", intf.vlan)
                ethernet_vars.add("V4_ADDRESS", "")
                ethernet_vars.add("V6_ADDRESS", "")
                ethernet_vars.add("USE_PIM", "False")
            else:
                # This is an edge interface.
                ethernet_vars.add("VLAN", "")

                ethernet_vars.add("V4_ADDRESS", list(intf.ip.address)[sindex])
                if intf.ipv6.address and len(list(intf.ipv6.address)) > 0:
                    ethernet_vars.add("V6_ADDRESS", list(intf.ipv6.address)[sindex])
                else:
                    ethernet_vars.add("V6_ADDRESS", "")

            if self.service.pim.rp and self.service.pim.rp != "":
                ethernet_vars.add("USE_PIM", "True")
            else:
                ethernet_vars.add("USE_PIM", "False")

            self.log.info(f"Applying template ethernet-base-cfg with vars {dict(ethernet_vars)}")
            ethernet_templ.apply("ethernet-base-cfg", ethernet_vars)

    def setup_local_users(self, dc, switch):
        """
        Configure the local users.
        """

        self.log.info(f"CAlling setup_local_users for DC {dc.id} with switch ID {switch.id}, name {switch.device}")

        user_vars = ncs.template.Variables()
        user_templ = ncs.template.Template(self.service)

        user_vars.add("DEVICE", switch.device)

        for user in self.service.security.user:
            user_vars.add("USERNAME", user.name)
            user_vars.add("USER_PASSWORD", decrypt(user.password))
            user_vars.add("USER_ROLE", user.role)

            self.log.info(f"Applying template nx-user-cfg with vars {dict(user_vars)}")
            user_templ.apply("nx-user-cfg", user_vars)

    def setup_aaa(self, dc, switch):
        """
        Configure AAA parameters on a switch.
        """

        self.log.info(f"Calling setup_aaa for DC {dc.id} with switch ID {switch.id}, name {switch.device}")

        aaa_vars = ncs.template.Variables()
        aaa_templ = ncs.template.Template(self.service)

        aaa_vars.add("DEVICE", switch.device)
        aaa_vars.add("MGMT_INTF", MGMT_INTF)

        self.log.info(f"Applying template aaa-base-cfg with vars {dict(aaa_vars)}")
        aaa_templ.apply("aaa-base-cfg", aaa_vars)

        for server in self.service.security.aaa.server:
            self.setup_aaa_server(dc, switch, server)

    def setup_aaa_server(self, dc, switch, server):
        """
        Configure AAA server parameters on a switch.
        """

        self.log.info(f"Calling setup_aaa_server for DC {dc.id} with switch ID {switch.id}, name {switch.device}, server {server}")

        server_vars = ncs.template.Variables()
        server_templ = ncs.template.Template(self.service)

        server_vars.add("DEVICE", switch.device)
        server_vars.add("SERVER", server)
        server_vars.add("KEY", decrypt(self.service.security.aaa.tacplus_key))

        self.log.info(f"Applying aaa-server-cfg with vars {dict(server_vars)}")
        server_templ.apply("aaa-server-cfg", server_vars)

    def setup_ntp(self, dc, device):
        """
        Configure NTP parameters on a device.
        """

        self.log.info(f"Calling setup_ntp for DC {dc.id}, device {device.device}")

        ntp_vars = ncs.template.Variables()
        ntp_templ = ncs.template.Template(self.service)

        templ_name = "{platform}-ntp-base-cfg"

        platform = get_platform(self.root, device)
        if platform == "nx-os":
            templ_name = templ_name.format(platform="nx")
        elif platform == "ucsm":
            templ_name = None
        else:
            raise ValueError(f"Platform {platform} is not supported.")

        if templ_name:
            ntp_vars.add("DEVICE", device.device)
            ntp_vars.add("MGMT_INTF", MGMT_INTF)

            self.log.info(f"Applying template {templ_name} with vars {dict(ntp_vars)}")
            ntp_templ.apply(templ_name, ntp_vars)

        for server in self.service.ntp.server:
            self.setup_ntp_server(dc, device, server)

    def setup_ntp_server(self, dc, device, server):
        """
        Configure NTP server parameters on a device.
        """

        self.log.info(f"Calling setup_ntp_server for DC {dc.id}, device {device.device}, server {server}")

        server_vars = ncs.template.Variables()
        server_templ = ncs.template.Template(self.service)

        templ_name = "{platform}-ntp-server-cfg"

        platform = get_platform(self.root, device)
        if platform == "nx-os":
            templ_name = templ_name.format(platform="nx")
        elif platform == "ucsm":
            templ_name = templ_name.format(platform="ucs")
        else:
            raise ValueError(f"Platform {platform} is not supported.")

        if not templ_name:
            return

        server_vars.add("DEVICE", device.device)
        server_vars.add("SERVER", server)

        self.log.info(f"Applying template {templ_name} for server {server}")
        server_templ.apply(templ_name, server_vars)

    def setup_snmp(self, dc, device):
        """
        Configure SNMP parameters on a device.
        """

        self.log.info(f"Calling setup_snmp for DC {dc.id}, device {device.device}")

        snmp_vars = ncs.template.Variables()
        snmp_templ = ncs.template.Template(self.service)

        templ_name = "{platform}-snmp-base-cfg"

        platform = get_platform(self.root, device)
        if platform == "nx-os":
            templ_name = templ_name.format(platform="nx")
        elif platform == "ucsm":
            templ_name = templ_name.format(platform="ucs")
        else:
            raise ValueError(f"Platform {platform} is not supported.")

        snmp_vars.add("DEVICE", device.device)
        snmp_vars.add("CONTACT", self.service.contact)
        snmp_vars.add("LOCATION", dc.location)
        snmp_vars.add("USER", self.service.snmp.user)
        snmp_vars.add("PASSWORD", decrypt(self.service.snmp.password))
        snmp_vars.add("MGMT_INTF", MGMT_INTF)

        if self.service.snmp.community and self.service.snmp.community != "":
            snmp_vars.add("COMMUNITY", decrypt(self.service.snmp.community))
        else:
            snmp_vars.add("COMMUNITY", "")

        self.log.info(f"Applying template {templ_name} with vars {dict(snmp_vars)}")
        snmp_templ.apply(templ_name, snmp_vars)

    def setup_logging(self, dc, device):
        """
        Configure logging parameters on a switch.
        """

        self.log.info(f"Calling setup_logging for DC {dc.id}, device {device.device}")

        logging_vars = ncs.template.Variables()
        logging_templ = ncs.template.Template(self.service)

        templ_name = "{platform}-logging-base-cfg"

        platform = get_platform(self.root, device)
        if platform == "nx-os":
            templ_name = templ_name.format(platform="nx")
        elif platform == "ucsm":
            templ_name = None
        else:
            raise ValueError(f"Platform {platform} is not supported.")

        if templ_name:
            logging_vars.add("DEVICE", device.device)
            m = re.search(r"\d", MGMT_INTF)
            num_start = m.start()
            logging_vars.add("MGMT_INTF_TYPE", MGMT_INTF[0:num_start])
            logging_vars.add("MGMT_INTF_ID", MGMT_INTF[num_start:])

            self.log.info(f"Applying template {templ_name} with vars {dict(logging_vars)}")
            logging_templ.apply(templ_name, logging_vars)

        for idx, server in enumerate(self.service.logging.server):
            self.setup_logging_server(dc, device, idx + 1, server)

    def setup_logging_server(self, dc, device, idx, server):
        """
        Configure logging server parameters on a device.
        """

        self.log.info(f"Calling setup_logging_server for DC {dc.id}, device {device.device}, server {server}")

        server_vars = ncs.template.Variables()
        server_templ = ncs.template.Template(self.service)

        templ_name = "{platform}-logging-server-cfg"

        platform = get_platform(self.root, device)
        if platform == "nx-os":
            templ_name = templ_name.format(platform="nx")
        elif platform == "ucsm":
            templ_name = templ_name.format(platform="ucs")
        else:
            raise ValueError(f"Platform {platform} is not supported.")

        if not templ_name:
            return

        if idx > 3 and platform == "ucsm":
            self.log.warning(f"WARNING: Not adding syslog server {server} as there are already 3 servers defined for {device.device}")
            return

        server_vars.add("DEVICE", device.device)
        server_vars.add("SERVER", server)
        server_vars.add("SERVER_NUM", idx)

        self.log.info(f"Applying template {templ_name} with vars {dict(server_vars)}")
        server_templ.apply(templ_name, server_vars)

    def setup_ospf(self, dc, switch):
        """
        Configure OSPF parameters on a switch.
        """

        self.log.info(f"Calling setup_ospf for DC {dc.id} with switch ID {switch.id}, name {switch.device}")

        ospf_vars = ncs.template.Variables()
        ospf_templ = ncs.template.Template(self.service)

        ospf_vars.add("DEVICE", switch.device)
        ospf_vars.add("BANDWIDTH", int(self.service.bandwidth / (1000 * 1000)))
        ospf_vars.add("KEY", decrypt(self.service.security.ospf_key))

        v4_subnet = ipaddress.ip_network(self.service.management.interface.v4_subnet)
        v4_addr = list(v4_subnet.hosts())[0]

        v4_addr += get_switch_octet(dc.id, switch.id)
        ospf_vars.add("ROUTER_ID", v4_addr)

        self.log.info(f"Applying template ospf-base-cfg with vars {dict(ospf_vars)}")
        ospf_templ.apply("ospf-base-cfg", ospf_vars)

    def setup_dns(self, dc, device):
        """
        Configure global DNS parameters on a device.
        """

        self.log.info(f"Calling setup_dns for DC {dc.id}, device {device.device}")

        dns_vars = ncs.template.Variables()
        dns_templ = ncs.template.Template(self.service)

        templ_name = "{platform}-dns-base-cfg"

        platform = get_platform(self.root, device)
        if platform == "nx-os":
            templ_name = templ_name.format(platform="nx")
        elif platform == "ucsm":
            templ_name = None
        else:
            raise ValueError(f"Platform {platform} is not supported.")

        if templ_name:
            dns_vars.add("DEVICE", device.device)
            dns_vars.add("DOMAIN", self.service.dns.domain)

            self.log.info(f"Applying template {templ_name} with vars {dict(dns_vars)}")
            dns_templ.apply(templ_name, dns_vars)

        for domain in self.service.dns.search_list:
            self.setup_dns_search(dc, device, domain)

        for server in self.service.dns.server:
            self.setup_dns_server(dc, device, server)

    def setup_dns_search(self, dc, device, domain):
        """
        Configure DNS search domain on a device.
        """

        self.log.info(f"Calling setup_dns_search for DC {dc.id}, device {device.device}, domain {domain}")

        search_vars = ncs.template.Variables()
        search_templ = ncs.template.Template(self.service)

        templ_name = "{platform}-dns-search-cfg"

        platform = get_platform(self.root, device)
        if platform == "nx-os":
            templ_name = templ_name.format(platform="nx")
        elif platform == "ucsm":
            templ_name = None
        else:
            raise ValueError(f"Platform {platform} is not supported.")

        if not templ_name:
            return

        search_vars.add("DEVICE", device.device)
        search_vars.add("DOMAIN", domain)

        self.log.info(f"Applying template {templ_name} with vars {dict(search_vars)}")
        search_templ.apply(templ_name, search_vars)

    def setup_dns_server(self, dc, device, server):
        """
        Configure DNS server on a device.
        """

        self.log.info(f"Calling setup_dns_server for DC {dc.id}, device {device.device}, server {server}")

        server_vars = ncs.template.Variables()
        server_templ = ncs.template.Template(self.service)

        templ_name = "{platform}-dns-server-cfg"

        platform = get_platform(self.root, device)
        if platform == "nx-os":
            templ_name = templ_name.format(platform="nx")
        elif platform == "ucsm":
            templ_name = templ_name.format(platform="ucs")
        else:
            raise ValueError(f"Platform {platform} is not supported.")

        if not templ_name:
            return

        server_vars.add("DEVICE", device.device)
        server_vars.add("SERVER", server)

        self.log.info(f"Applying template {templ_name} with vars {dict(server_vars)}")
        server_templ.apply(templ_name, server_vars)

    def setup_fi_vlan(self, dc, fi):
        """
        Configure VLAN parameters on an FI.
        """

        self.log.info(f"Calling setup_fi_vlan for DC {dc.id}, FI {fi.device}")

        vlan_vars = ncs.template.Variables()
        vlan_templ = ncs.template.Template(self.service)

        vlan_vars.add("DEVICE", fi.device)

        for vlan in self.service.vlan:
            vlan_vars.add("VLAN_ID", vlan.id)
            vlan_vars.add("VLAN_NAME", vlan.name.format(dc=dc.id, peer_dc=get_peer_id(dc.id)))

            self.log.info(f"Applying template ucs-vlan-cfg with vars {dict(vlan_vars)}")
            vlan_templ.apply("ucs-vlan-cfg", vlan_vars)

    def setup_fi_vnic_templ(self, dc, fi):
        """
        Configure the VNIC templates for a given FI.
        """

        self.log.info(f"Calling setup_fi_vnic_templ for DC {dc.id}, FI {fi.device}")

        vnic_vars = ncs.template.Variables()
        vnic_templ = ncs.template.Template(self.service)

        vnic_vars.add("DEVICE", fi.device)

        for templ in fi.vnic_template_trunk:
            if "ciscolive:org" in templ and templ.org:
                vnic_vars.add("UCS_ORG", templ.org)
                vnic_vars.add("UCS_VNIC_TEMPLATE", templ.vnic_template)
            else:
                vnic_vars.add("UCS_ORG", "")
                vnic_vars.add("UCS_VNIC_TEMPLATE", templ.root_vnic_template)

            for vlan in self.service.vlan:
                vnic_vars.add("NATIVE", "no")
                vnic_vars.add("VLAN_NAME", vlan.name.format(dc=dc.id, peer_dc=get_peer_id(dc.id)))
                if templ.needs_native and vlan.native:
                    vnic_vars.add("NATIVE", "yes")

                self.log.info(f"Applying template ucs-vlan-vnic-templ-cfg with vars {dict(vnic_vars)}")
                vnic_templ.apply("ucs-vlan-vnic-templ-cfg", vnic_vars)

    def setup_mgmt_acl(self, dc, switch):
        """
        Configure management ACLs on a switch.
        """

        self.log.info(f"Calling setup_mgmt_acl for DC {dc.id}, switch ID {switch.id}, name {switch.device}")

        acl_vars = ncs.template.Variables()
        acl_templ = ncs.template.Template(self.service)

        acl_vars.add("DEVICE", switch.device)

        for idx, network in enumerate(self.service.management.v4_network):
            seq = (idx + 1) * 10
            acl_vars.add("SEQ", seq)
            acl_vars.add("NETWORK", network)
            self.log.info(f"Applying template v4-mgmt-acl-cfg with vars {dict(acl_vars)}")
            acl_templ.apply("v4-mgmt-acl-cfg", acl_vars)

        for idx, network in enumerate(self.service.management.v6_network):
            seq = (idx + 1) * 10
            acl_vars.add("SEQ", seq)
            acl_vars.add("NETWORK", network)
            self.log.info(f"Applying template v6-mgmt-acl-cfg with vars {dict(acl_vars)}")
            acl_templ.apply("v6-mgmt-acl-cfg", acl_vars)

    def setup_static_routing(self, dc, switch):
        """
        Configure static routes on a switch.
        """

        self.log.info(f"Calling setup_static_routing for DC {dc.id}, switch ID {switch.id}, name {switch.device}")

        route_vars = ncs.template.Variables()
        route_templ = ncs.template.Template(self.service)

        route_vars.add("DEVICE", switch.device)

        i = 1
        for route in self.service.routing.ip:
            if route.data_center and route.data_center != dc.id and route.data_center != "":
                continue

            route_vars.add("PREFIX", route.prefix)
            route_vars.add("DESTINATION", route.next_hop)
            if route.redistribute:
                route_vars.add("REDISTRIBUTE", "True")
                route_vars.add("SEQ", i * 10)
                i += 1
            else:
                route_vars.add("REDISTRIBUTE", "False")
                route_vars.add("SEQ", "")

            self.log.info(f"Applying template v4-routing-cfg with vars {dict(route_vars)}")
            route_templ.apply("v4-routing-cfg", route_vars)

        i = 1
        for route in self.service.routing.ipv6:
            if route.data_center and route.data_center != dc.id and route.data_center != "":
                continue

            route_vars.add("PREFIX", route.prefix)
            route_vars.add("DESTINATION", route.next_hop)
            if route.redistribute:
                route_vars.add("REDISTRIBUTE", "True")
                route_vars.add("SEQ", i * 10)
                i += 1
            else:
                route_vars.add("REDISTRIBUTE", "False")
                route_vars.add("SEQ", "")

            self.log.info(f"Applying template v6-routing-cfg with vars {dict(route_vars)}")
            route_templ.apply("v6-routing-cfg", route_vars)

    def setup_vcenter_vlans(self, dc, vcenter):
        """
        Setup VLANs on port-groups in vCenter.
        """

        self.log.info(f"Calling setup_vcenter_vlans for DC {dc.id}")

        vc_vars = ncs.template.Variables()
        vc_templ = ncs.template.Template(self.service)

        vc_vars.add("DEVICE", vcenter.device)
        vc_vars.add("DATACENTER", vcenter.datacenter.name)

        for vlan in self.service.vlan:
            if vlan.category != "vm":
                continue

            vc_vars.add("VLAN_ID", vlan.id)
            vc_vars.add("PG_NAME", vlan.name.format(dc=dc.id, peer_dc=get_peer_id(dc.id)))

            if vlan.cross_dc:
                vc_vars.add("VSWITCH", vcenter.datacenter.cross_dc_vswitch)
            else:
                vc_vars.add("VSWITCH", list(vcenter.datacenter.dc_vswitch)[int(dc.id) - 1])

            self.log.info(f"Applying template vc-portgroup-cfg with vars {dict(vc_vars)}")
            vc_templ.apply("vc-portgroup-cfg", vc_vars)
