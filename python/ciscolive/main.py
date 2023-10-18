# -*- mode: python; python-indent: 4 -*-
import ncs  # type:  ignore
from ncs.application import Service  # type:  ignore
from .ciscolive_create import CiscoLiveServiceCreate
from .ciscolive_tool import CiscoLiveToolServerAction, CiscoLiveToolAclAction
from .ciscolive_netbox import CiscoLiveNetboxServerAction, CiscoLiveNetboxVlanAction


class CiscoLiveToolServerServiceCreate(Service):
    @Service.create
    def cb_create(self, tctx, root, service, proplist):
        self.log.info("Service create(service=", service._path, ")")

        # Use the provided connection details for the server to craft the URL to connect to
        if service.fqdn:
            tool_url = f"{service.protocol}://{service.fqdn}:{service.port}"
        else:
            tool_url = f"{service.protocol}://{service.address}:{service.port}"
        self.log.info(f"Tool URL: {tool_url}")
        # TODO: After restarting NSO this value seems to go away until re-commit
        service.url = tool_url


class CiscoLiveNetboxServerServiceCreate(Service):
    @Service.create
    def cb_create(self, tctx, root, service, proplist):
        self.log.info("Service create(service=", service._path, ")")

        # Use the provided connection details for the server to craft the URL to connect to
        if service.fqdn:
            netbox_url = f"{service.protocol}://{service.fqdn}:{service.port}"
        else:
            netbox_url = f"{service.protocol}://{service.address}:{service.port}"
        self.log.info(f"NetBox URL: {netbox_url}")
        # TODO: After restarting NSO this value seems to go away until re-commit
        service.url = netbox_url


# ---------------------------------------------
# COMPONENT THREAD THAT WILL BE STARTED BY NCS.
# ---------------------------------------------
class Main(ncs.application.Application):
    def setup(self):
        # The application class sets up logging for us. It is accessible
        # through 'self.log' and is a ncs.log.Log instance.
        self.log.info("Main RUNNING")

        # Service callbacks require a registration for a 'service point',
        # as specified in the corresponding data model.
        #
        self.register_service("ciscolive-tool-server-servicepoint", CiscoLiveToolServerServiceCreate)
        self.register_service("ciscolive-netbox-server-servicepoint", CiscoLiveNetboxServerServiceCreate)
        self.register_service("ciscolive-servicepoint", CiscoLiveServiceCreate)

        # Register Action callbacks
        self.register_action("tool-verify-status", CiscoLiveToolServerAction)
        self.register_action("netbox-verify-status", CiscoLiveNetboxServerAction)
        self.register_action("netbox-sync-vlans", CiscoLiveNetboxVlanAction)
        self.register_action("tool-sync-acls", CiscoLiveToolAclAction)

        # If we registered any callback(s) above, the Application class
        # took care of creating a daemon (related to the service/action point).

        # When this setup method is finished, all registrations are
        # considered done and the application is 'started'.

    def teardown(self):
        # When the application is finished (which would happen if NCS went
        # down, packages were reloaded or some error occurred) this teardown
        # method will be called.

        self.log.info("Main FINISHED")
