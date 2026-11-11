"""list-effective-deployments-nonexistent-core-device-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-effective-deployments-nonexistent-core-device-not-found"
GROUP = "error-semantics"
SERVICES = ["greengrassv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEffectiveDeployments for a never-registered core device returns an empty list, while
    GetCoreDevice on it raises ResourceNotFoundException ("<name> can not be found") and
    ListDeployments answers normally.
    """
    gg = ctx.client("greengrassv2")
    thing_name = ctx.unique_name("sim2real-gg-noeffective-")

    resp = gg.list_effective_deployments(coreDeviceThingName=thing_name)
    assert resp.get("effectiveDeployments", []) == [], (
        f"expected no effective deployments for an unregistered core device, got {resp}"
    )

    code, message = _client_error(lambda: gg.get_core_device(coreDeviceThingName=thing_name))
    assert code == "ResourceNotFoundException", (
        f"GetCoreDevice on the identical unregistered thing name should reject where "
        f"ListEffectiveDeployments is lenient, got code={code!r}"
    )
    assert message == f"{thing_name} can not be found", f"got message={message!r}"

    listing = gg.list_deployments()
    assert "deployments" in listing, f"positive control: ListDeployments should respond normally, got {listing}"


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
