"""delete-origin-endpoint-twice-second-call-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-origin-endpoint-twice-second-call-not-found"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DeleteOriginEndpoint on a deleted Id fails NotFoundException with the exact message, as
    DescribeOriginEndpoint does, while an untouched endpoint on the same channel stays describable."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-chan-")
    mp.create_channel(Id=channel_id)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    target_id = ctx.unique_name("sim2real-mp-ep-target-")
    mp.create_origin_endpoint(
        Id=target_id, ChannelId=channel_id, HlsPackage={"SegmentDurationSeconds": 6}
    )
    sibling_id = ctx.unique_name("sim2real-mp-ep-sibling-")
    mp.create_origin_endpoint(
        Id=sibling_id, ChannelId=channel_id, HlsPackage={"SegmentDurationSeconds": 6}
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=sibling_id))

    mp.delete_origin_endpoint(Id=target_id)

    listed = mp.list_origin_endpoints(ChannelId=channel_id)
    assert target_id not in {ep["Id"] for ep in listed["OriginEndpoints"]}, (
        "deleted endpoint still present in ListOriginEndpoints"
    )
    describe_code, describe_message = _error_code(lambda: mp.describe_origin_endpoint(Id=target_id))
    assert describe_code == "NotFoundException", (
        f"expected deleted endpoint to 404 on an independent describe, got {describe_code!r}"
    )
    expected_message = f"originEndpoint with id={target_id} not found"
    assert describe_message == expected_message, (
        f"expected message {expected_message!r}, got {describe_message!r}"
    )

    code, message = _error_code(lambda: mp.delete_origin_endpoint(Id=target_id))
    assert code == "NotFoundException", "deleting an already-deleted endpoint must 404, not succeed silently"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    described_sibling = mp.describe_origin_endpoint(Id=sibling_id)
    assert described_sibling["Id"] == sibling_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
