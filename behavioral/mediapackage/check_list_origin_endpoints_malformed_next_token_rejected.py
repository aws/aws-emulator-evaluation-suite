"""list-origin-endpoints-malformed-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-origin-endpoints-malformed-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListOriginEndpoints with a NextToken that is not an opaque token this API ever issued
    is rejected with UnprocessableEntityException; the same call with no NextToken still
    lists the real endpoint (positive control) in the same run."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    mp.create_channel(Id=channel_id, Tags={"created-by": "sim2real"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    endpoint_id = ctx.unique_name("sim2real-mp-oe-")
    mp.create_origin_endpoint(
        Id=endpoint_id, ChannelId=channel_id, HlsPackage={}, Tags={"created-by": "sim2real"}
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=endpoint_id))

    # Positive control first: the unpaginated call must succeed and see the endpoint, so a
    # rejection below is attributable to the bogus token and not to every call to this API.
    baseline = mp.list_origin_endpoints(ChannelId=channel_id)
    baseline_ids = [e["Id"] for e in baseline["OriginEndpoints"]]
    assert endpoint_id in baseline_ids, (
        f"baseline ListOriginEndpoints(ChannelId={channel_id!r}) must include the endpoint "
        f"just created, got ids {baseline_ids!r}"
    )

    error = _unprocessable(
        lambda: mp.list_origin_endpoints(ChannelId=channel_id, NextToken="not-a-real-token!!")
    )
    code = error.get("Code")
    assert code == "UnprocessableEntityException", (
        f"expected UnprocessableEntityException for a NextToken mediapackage never issued, "
        f"got {code!r} (full error: {error!r})"
    )
    message = error.get("Message")
    assert message == "Invalid NextToken", f"expected message 'Invalid NextToken', got {message!r}"


def _unprocessable(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised. An unexpected SUCCESS
    raises, because an emulator accepting a token real MediaPackage refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(
        f"a NextToken mediapackage never issued must be refused, but the call SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
