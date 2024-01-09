import ncs  # type: ignore
from ncs.dp import Action  # type: ignore
from _ncs import decrypt  # type: ignore
import _ncs  # type: ignore
import re
import json
from typing import Any
from .utils import get_users_groups, form_login, get_switch_octet


class CiscoLiveToolServerAction(Action):
    @Action.action
    def cb_action(self, uinfo, name, kp, action_input, action_output, trans):
        self.log.info("ToolAction: ", name)
        service = ncs.maagic.get_node(trans, kp)
        root = ncs.maagic.get_root(trans)
        trans.maapi.install_crypto_keys()

        if name == "verify-status":
            self.verify_status(service, root, action_output)

    def verify_status(self, service, root, action_output):
        """Perform a status check that The Tool is reachable."""
        s = None
        try:
            s, _ = form_login(
                service.url + service.login_uri,
                request={"return_url": "/", "username": service.username, "password": decrypt(service.password)},
                timeout=10,
                verify=False,  # TODO: Remove this when the certificate has been renewed.
            )
        except Exception as e:
            action_output.success = False
            action_output.output = f"Failed to query Tool: {e}"
            self.log.exception("Failed to query Tool: %s" % str(e))
        else:
            action_output.success = True
            action_output.output = "Tool is UP"
        finally:
            if s:
                s.close()

        self.log.info(f"Verification Results: {action_output.success} {action_output.output}")


class CiscoLiveToolAclAction(Action):
    def convert_acl(self, acl_blob: str, service: Any) -> str:
        """Convert an IOS-XE ACL into NX-OS.

        Additionally, any macros are substitued.
        """
        acl_lines = []
        aclno = 10
        for line in acl_blob.split("\n"):
            line = line.rstrip()
            if re.search(r"^\s*!", line):
                # Skip IOS comments.
                continue

            # First substitute known macros.
            # The special macro, {Device.LOC_NR}, will remain.
            for macro, sub in {
                "DNS_Server1": list(service.dns.server)[0],
                "DNS_Server2": list(service.dns.server)[1],
                "NTP_Server1": list(service.ntp.server)[0],
                "NTP_Server2": list(service.ntp.server)[1],
                "IPV6_PREFIX": str(service.ip_info.v6_network).rstrip(":"),
            }.items():
                line = re.sub(rf"\{{{macro}}}", sub, line, flags=re.I)

            # Translate any keywords.
            for keyw, sub in {"mld-v2-report": "mldv2"}.items():
                line = re.sub(rf"\b{keyw}\b", sub, line, flags=re.I)

            m = re.search(r"(\{[^}]+})", line)
            if m and m.group(1) != "{Device.LOC_NR}":
                self.log.warning(f"Skipping line '{line}' as it has unknown macro {m.group(1)}")
                line = f" remark Skipping {line.lstrip()}"

            # Remove the "extended" keyword, not used in NX-OS.
            m = re.search(r"^ip access-list extended (.+)$", line)
            if m:
                acl_lines.append(f"ip access-list {m.group(1)}")
                continue

            if re.search(r"^\s", line):
                acl_lines.append(f"{aclno} {line}")
                aclno += 10
            else:
                acl_lines.append(line)

        return "\n".join(acl_lines)

    @Action.action
    def cb_action(self, uinfo, name, kp, action_input, action_output, trans):
        self.log.info("ToolAclAction:", name)
        service = ncs.maagic.get_node(trans, kp)
        root = ncs.maagic.get_root(trans)
        trans.maapi.install_crypto_keys()
        tool_server = root.tool_server[service.tool_server]
        tool_api = tool_server.url + tool_server.api_endpoint

        ugroups = get_users_groups(trans, uinfo)
        self.log.info(f"User groups are {ugroups}")

        session = None

        if True:
            try:
                session, _ = form_login(
                    tool_server.url + tool_server.login_uri,
                    request={"return_url": "/", "username": tool_server.username, "password": decrypt(tool_server.password)},
                    verify=False,  # TODO: Remove this when the certificate has been renewed.
                )
            except Exception as e:
                action_output.success = False
                action_output.output = f"Failed to authenticate to the Tool: {e}"
                return

        dry_run = {}
        acl_config = ""

        for acl in (service.security.v4_attendee_acl, service.security.v6_attendee_acl):
            if True:
                try:
                    response = session.get(tool_api + acl, verify=False)
                    response.raise_for_status()
                except Exception as e:
                    action_output.success = False
                    action_output.output = f"Failed to retrieve {acl} from the Tool: {e}"
                    session.close()
                    return

                # We can't use this since the JSON is bad.
                # config_ele = response.json()
                config_ele = json.loads(re.sub(r"\t", " ", response.text))
            else:
                # while testing, use a file instead.
                with open(f"{acl}.json", "r") as fd:
                    try:
                        config_ele = json.load(fd)
                    except Exception as e:
                        action_output.output = f"Failed to load {acl}.json: {e}"
                        action_output.success = False
                        return

            acl_config += self.convert_acl(config_ele["AddConfiguration"], service) + "\n"

        with ncs.maapi.Maapi() as m:
            with ncs.maapi.Session(m, user=uinfo.username, context=name, groups=ugroups):
                with m.start_write_trans() as t:
                    for dc in service.data_center:
                        for switch in dc.switch:
                            switch_acl = re.sub(r"\{Device.LOC_NR}", str(get_switch_octet(dc.id, switch.id)), acl_config, flags=re.I)
                            _ncs.maapi.load_config_cmds(
                                m.msock,
                                t.th,
                                _ncs.maapi.CONFIG_MERGE | _ncs.maapi.CONFIG_C_IOS,
                                switch_acl,
                                path=f"/ncs:devices/device{{{switch.device}}}/config",
                            )

                    if action_input.commit:
                        t.apply()
                    else:
                        cp = ncs.maapi.CommitParams()
                        cp.dry_run_native()
                        # Merge the dry run from this switch into the global dry run output.
                        dry_run = t.apply_params(True, cp)

        if action_input.commit:
            action_output.output = "Commit done."
        else:
            action_output.output = json.dumps(dry_run, indent=2).replace("\\n", "\n")

        action_output.success = True

        if session:
            session.close()
