"""core-device-scoped-ops-lenient-for-nonexistent-device."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "core-device-scoped-ops-lenient-for-nonexistent-device"
GROUP = "state"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """For an unregistered core device, ListEffectiveDeployments, ListInstalledComponents and
    BatchDisassociateClientDeviceFromCoreDevice return empty results, while GetCoreDevice raises
    ResourceNotFoundException ("<name> can not be found").
    """
    ggv2 = ctx.client("greengrassv2")
    bogus = ctx.unique_name("sim2real-ggv2-nonexistent-core-")

    effective = ggv2.list_effective_deployments(coreDeviceThingName=bogus)
    assert effective.get("effectiveDeployments", []) == [], effective

    installed = ggv2.list_installed_components(coreDeviceThingName=bogus)
    assert installed.get("installedComponents", []) == [], installed

    disassoc = ggv2.batch_disassociate_client_device_from_core_device(
        coreDeviceThingName=bogus,
        entries=[{"thingName": ctx.unique_name("sim2real-ggv2-client-")}],
    )
    assert disassoc.get("errorEntries", []) == [], disassoc

    # Consistency check: singular-resource operations on the same bogus name DO validate
    # existence, unlike the list/batch operations above.
    code, message = _client_error(lambda: ggv2.get_core_device(coreDeviceThingName=bogus))
    assert code == "ResourceNotFoundException", code
    assert message == f"{bogus} can not be found", f"got message={message!r}"


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
