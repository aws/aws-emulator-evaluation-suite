"""core-device-nucleus-native-protocol-unreachable."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "core-device-nucleus-native-protocol-unreachable"
GROUP = "native-protocol"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Registering an IoT thing creates no Greengrass core device: GetCoreDevice raises
    ResourceNotFoundException with the exact message and ListCoreDevices does not list it.
    """
    ggv2 = ctx.client("greengrassv2")
    iot = ctx.client("iot")

    thing_name = ctx.unique_name("sim2real-ggv2-never-checked-in-")
    iot.create_thing(thingName=thing_name)
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    # Positive control: the thing is a genuine, independently-readable IoT registry entry --
    # an emulator that silently no-op'd CreateThing could otherwise pass the absence checks
    # below for the wrong reason (there being no thing at all, rather than an uncheck-in'd one).
    described = iot.describe_thing(thingName=thing_name)
    assert described["thingName"] == thing_name, described

    # No Nucleus process ever ran or checked in for this thing, so Greengrass must not have a
    # core device record for it.
    code, message = _error_code(lambda: ggv2.get_core_device(coreDeviceThingName=thing_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a thing with no Nucleus check-in, got {code!r}"
    )
    expected = f"{thing_name} can not be found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    all_core_device_names = _list_all_core_device_names(ggv2)
    assert thing_name not in all_core_device_names, (
        f"{thing_name} was never checked in by a Nucleus but showed up in ListCoreDevices"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _list_all_core_device_names(ggv2, page_cap: int = 20) -> set:
    names: set = set()
    next_token = None
    for _ in range(page_cap):
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = ggv2.list_core_devices(**kwargs)
        names.update(d["coreDeviceThingName"] for d in resp["coreDevices"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
