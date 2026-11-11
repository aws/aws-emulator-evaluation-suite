"""delete-channel-with-endpoints-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-channel-with-endpoints-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteChannel on a Channel that still has an associated OriginEndpoint is
    rejected with UnprocessableEntityException, the channel remains intact, and once
    the endpoint is removed the same DeleteChannel call succeeds (positive control)."""
    mp = ctx.client("mediapackage")

    channel_id = ctx.unique_name("sim2real-mp-delrej-")
    mp.create_channel(Id=channel_id, Tags={"sim2real-check": "delete-channel-with-endpoints-rejected"})

    origin_id = ctx.unique_name("sim2real-mp-oe-")
    mp.create_origin_endpoint(
        Id=origin_id,
        ChannelId=channel_id,
        HlsPackage={},
        Tags={"sim2real-check": "delete-channel-with-endpoints-rejected"},
    )

    def _cleanup():
        # best-effort: resources may already be deleted by the check body itself
        try:
            mp.delete_origin_endpoint(Id=origin_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        try:
            mp.delete_channel(Id=channel_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    code, message = _error_code(lambda: mp.delete_channel(Id=channel_id))
    assert code == "UnprocessableEntityException", (
        f"DeleteChannel on a channel with an associated OriginEndpoint should be rejected with "
        f"UnprocessableEntityException, got {code!r}"
    )
    expected_message = "channel cannot be deleted because 1 OriginEndpoint is attached to it"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: channel still exists
    described = mp.describe_channel(Id=channel_id)
    assert described["Id"] == channel_id, (
        f"the rejected DeleteChannel should leave the channel intact, but DescribeChannel returned "
        f"{described!r}"
    )

    # positive control: remove the blocking origin endpoint, then delete succeeds
    mp.delete_origin_endpoint(Id=origin_id)
    deadline = time.monotonic() + 60
    gone = False
    while time.monotonic() < deadline:
        try:
            mp.describe_origin_endpoint(Id=origin_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                gone = True
                break
            raise
        time.sleep(3)
    assert gone, "origin endpoint deletion did not complete within 60s"

    mp.delete_channel(Id=channel_id)
    final_code, final_message = _error_code(lambda: mp.describe_channel(Id=channel_id))
    assert final_code == "NotFoundException", (
        f"DeleteChannel succeeded once the blocking endpoint was removed, but DescribeChannel "
        f"afterwards returned {final_code!r} instead of NotFoundException"
    )
    expected_final = f"channel with id={channel_id} not found"
    assert final_message == expected_final, f"expected message {expected_final!r}, got {final_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
