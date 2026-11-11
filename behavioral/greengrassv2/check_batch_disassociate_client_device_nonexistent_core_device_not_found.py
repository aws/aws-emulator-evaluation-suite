"""batch-disassociate-client-device-nonexistent-core-device-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-disassociate-client-device-nonexistent-core-device-not-found"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDisassociateClientDeviceFromCoreDevice for a thing never registered as a core device
    succeeds with empty errorEntries, and ListClientDevicesAssociatedWithCoreDevice for it
    returns an empty list.
    """
    gg = ctx.client("greengrassv2")
    thing_name = ctx.unique_name("sim2real-gg-nocore-disassoc-")

    resp = gg.batch_disassociate_client_device_from_core_device(
        coreDeviceThingName=thing_name,
        entries=[{"thingName": ctx.unique_name("sim2real-gg-clientdevice-")}],
    )
    error_entries = resp.get("errorEntries", [])
    assert error_entries == [], (
        f"expected an empty errorEntries list for a disassociate against a core device that "
        f"never registered, got {error_entries!r}"
    )

    # Independent read at the destination: the lenient disassociate must not have fabricated
    # a registration for the never-registered core device.
    code, associated = _error_code_or_response(
        lambda: gg.list_client_devices_associated_with_core_device(
            coreDeviceThingName=thing_name
        )
    )
    assert code is None, (
        f"expected ListClientDevicesAssociatedWithCoreDevice to also answer leniently (no "
        f"raised exception) for the never-registered core device, got code={code!r}"
    )
    devices = associated.get("associatedClientDevices", [])
    assert devices == [], (
        f"expected no recorded association for a never-registered core device, got {devices!r}"
    )


def _error_code_or_response(fn):
    try:
        return None, fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
