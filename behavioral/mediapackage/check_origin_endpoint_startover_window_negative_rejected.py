"""origin-endpoint-startover-window-negative-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "origin-endpoint-startover-window-negative-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOriginEndpoint with a negative StartoverWindowSeconds is rejected with
    UnprocessableEntityException, no endpoint is persisted, and a valid non-negative
    value on the same Id succeeds (positive control)."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-sw-")
    mp.create_channel(Id=cid)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))

    oid = ctx.unique_name("sim2real-mp-oe-")
    code, message = _error_code(
        lambda: mp.create_origin_endpoint(
            Id=oid, ChannelId=cid, HlsPackage={}, StartoverWindowSeconds=-100
        )
    )
    assert code == "UnprocessableEntityException", (
        f"expected UnprocessableEntityException for a negative StartoverWindowSeconds, got {code}"
    )
    expected_message = "startoverWindowSeconds must be greater than or equal to 300"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no origin endpoint was persisted under this Id
    not_found_code, not_found_message = _error_code(lambda: mp.describe_origin_endpoint(Id=oid))
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException for the rejected Id, got {not_found_code}"
    )
    expected_not_found = f"originEndpoint with id={oid} not found"
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )

    # positive control: a valid non-negative value succeeds, and the same Id is reusable
    # (proving the earlier rejection did not reserve or partially persist the Id)
    created = mp.create_origin_endpoint(
        Id=oid, ChannelId=cid, HlsPackage={}, StartoverWindowSeconds=3600
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=oid))
    assert created["StartoverWindowSeconds"] == 3600, (
        f"expected the create response to echo StartoverWindowSeconds=3600, "
        f"got {created.get('StartoverWindowSeconds')}"
    )

    # terminal read: independent of the mutating call, at the destination
    described = mp.describe_origin_endpoint(Id=oid)
    assert described["StartoverWindowSeconds"] == 3600, (
        f"expected StartoverWindowSeconds=3600 to persist across a Describe call, "
        f"got {described.get('StartoverWindowSeconds')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
