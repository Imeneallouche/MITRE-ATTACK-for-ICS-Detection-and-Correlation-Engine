from app.utility.base_world import BaseWorld
from plugins.gems.app.gems_svc import GemsService

name = "GEMS"
description = "The Ground Equipment Monitoring Service (GEMS) plugin for Caldera provides adversary emulation abilities specific to the OMG-GEMS communication protocol."
address = "/plugin/gems/gui"
access = BaseWorld.Access.RED


async def enable(services):
    gems_svc = GemsService(services, name, description)
    app = services.get("app_svc").application
    app.router.add_route("GET", "/plugin/gems/gui", gems_svc.splash)
    app.router.add_route("GET", "/plugin/gems/data", gems_svc.plugin_data)
