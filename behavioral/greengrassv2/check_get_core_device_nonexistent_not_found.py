"""get-core-device-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-core-device-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCoreDevice on a name never registered as a core device raises ResourceNotFoundException
    ("<name> can not be found"), while ListCoreDevices answers with a coreDevices list.
    """
    gg = ctx.client("greengrassv2")
    thing_name = ctx.unique_name("sim2real-ggv2-missing-core-")
    code, message = _client_error(lambda: gg.get_core_device(coreDeviceThingName=thing_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == f"{thing_name} can not be found", f"got message={message!r}"

    # Positive control: the general core-device API surface is otherwise healthy.
    listing = gg.list_core_devices()
    assert "coreDevices" in listing, listing


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
