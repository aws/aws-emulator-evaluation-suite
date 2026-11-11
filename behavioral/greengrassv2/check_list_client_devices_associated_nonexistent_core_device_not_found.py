"""list-client-devices-associated-nonexistent-core-device-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-client-devices-associated-nonexistent-core-device-not-found"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListClientDevicesAssociatedWithCoreDevice for a never-registered core device returns an empty
    associatedClientDevices list, not ResourceNotFoundException.
    """
    gg = ctx.client("greengrassv2")
    core_device_name = ctx.unique_name("sim2real-ggv2-missing-core-")
    resp = gg.list_client_devices_associated_with_core_device(coreDeviceThingName=core_device_name)
    assert resp["associatedClientDevices"] == [], (
        f"expected an empty associatedClientDevices page for an unregistered core device "
        f"(no ResourceNotFoundException), got {resp['associatedClientDevices']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
