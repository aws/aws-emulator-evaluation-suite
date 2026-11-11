"""create-origin-endpoint-nonexistent-channel-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-origin-endpoint-nonexistent-channel-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOriginEndpoint referencing a ChannelId that does not exist is
    rejected with NotFoundException, and no endpoint is left behind. Creating
    the same Id under a real channel succeeds (positive control, same file)."""
    mp = ctx.client("mediapackage")

    bogus_channel = ctx.unique_name("sim2real-mp-missing-chan-")
    endpoint_id = ctx.unique_name("sim2real-mp-ep-orphan-")

    code, message = _error_code(
        lambda: mp.create_origin_endpoint(
            Id=endpoint_id,
            ChannelId=bogus_channel,
            HlsPackage={"SegmentDurationSeconds": 6},
        )
    )
    assert code == "UnprocessableEntityException", f"unexpected error code: {code!r}"
    assert message == "channelId not found", f"expected message 'channelId not found', got {message!r}"

    listed = mp.list_origin_endpoints()
    assert endpoint_id not in {ep["Id"] for ep in listed["OriginEndpoints"]}, (
        "an OriginEndpoint was created despite its parent Channel not existing"
    )
    describe_code, describe_message = _error_code(lambda: mp.describe_origin_endpoint(Id=endpoint_id))
    assert describe_code == "NotFoundException", (
        f"expected NotFoundException describing the never-created endpoint, got {describe_code!r}"
    )
    expected_describe = f"originEndpoint with id={endpoint_id} not found"
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )

    real_channel = ctx.unique_name("sim2real-mp-real-chan-")
    mp.create_channel(Id=real_channel, Tags={"purpose": "behavioral-check"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=real_channel))
    mp.create_origin_endpoint(
        Id=endpoint_id,
        ChannelId=real_channel,
        HlsPackage={"SegmentDurationSeconds": 6},
        Tags={"purpose": "behavioral-check"},
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=endpoint_id))
    described = mp.describe_origin_endpoint(Id=endpoint_id)
    assert described["ChannelId"] == real_channel, (
        f"expected the endpoint to report its real parent channel {real_channel!r}, "
        f"got {described['ChannelId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
