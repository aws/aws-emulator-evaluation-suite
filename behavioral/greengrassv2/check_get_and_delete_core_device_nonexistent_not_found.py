"""get-and-delete-core-device-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-and-delete-core-device-nonexistent-not-found"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCoreDevice and GetCoreDevice on a name never registered as a core device raise
    ResourceNotFoundException with the exact message, and ListCoreDevices does not list it.
    """
    ggv2 = ctx.client("greengrassv2")
    bogus = ctx.unique_name("sim2real-ggv2-nonexistent-core-")

    expected = f"{bogus} can not be found"
    delete_code, delete_message = _error_code(lambda: ggv2.delete_core_device(coreDeviceThingName=bogus))
    assert delete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from DeleteCoreDevice on an unregistered "
        f"thing name, got {delete_code!r}"
    )
    assert delete_message == expected, f"expected message {expected!r}, got {delete_message!r}"
    get_code, get_message = _error_code(lambda: ggv2.get_core_device(coreDeviceThingName=bogus))
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetCoreDevice on an unregistered "
        f"thing name, got {get_code!r}"
    )
    assert get_message == expected, f"expected message {expected!r}, got {get_message!r}"

    # Positive control: the surrounding core-device API surface still functions, and the
    # bogus thing name — never registered — is not merely missing from a broken listing.
    listing = ggv2.list_core_devices()
    names = {device.get("coreDeviceThingName") for device in listing.get("coreDevices", [])}
    assert bogus not in names, (
        f"unregistered thing name {bogus!r} unexpectedly present in ListCoreDevices: {names!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
