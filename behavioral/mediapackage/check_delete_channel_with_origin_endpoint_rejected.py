"""delete-channel-with-origin-endpoint-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-channel-with-origin-endpoint-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteChannel fails UnprocessableEntityException with the exact message while an OriginEndpoint is
    attached and the channel stays; once the endpoint is gone the delete succeeds and DescribeChannel
    converges to NotFoundException with the exact message."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    mp.create_channel(Id=channel_id)
    channel_deleted = {"v": False}
    ctx.on_cleanup(lambda: None if channel_deleted["v"] else mp.delete_channel(Id=channel_id))

    endpoint_id = ctx.unique_name("sim2real-mp-oe-")
    mp.create_origin_endpoint(Id=endpoint_id, ChannelId=channel_id, HlsPackage={})
    endpoint_deleted = {"v": False}
    ctx.on_cleanup(lambda: None if endpoint_deleted["v"] else mp.delete_origin_endpoint(Id=endpoint_id))

    code, message = _error_code(lambda: mp.delete_channel(Id=channel_id))
    assert code == "UnprocessableEntityException", (
        f"expected UnprocessableEntityException while an OriginEndpoint exists, got {code}"
    )
    expected_message = "channel cannot be deleted because 1 OriginEndpoint is attached to it"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the channel is still present
    described = mp.describe_channel(Id=channel_id)
    assert described["Id"] == channel_id, f"expected {channel_id}, got {described.get('Id')}"

    # positive control: remove the child endpoint, then delete succeeds
    mp.delete_origin_endpoint(Id=endpoint_id)
    endpoint_deleted["v"] = True
    mp.delete_channel(Id=channel_id)
    channel_deleted["v"] = True

    # terminal read: independent of the mutating delete call, and DeleteChannel may be
    # asynchronous, so converge on the not-found code rather than assuming it is immediate.
    deadline = time.monotonic() + 60.0
    code_after_delete = message_after_delete = None
    while time.monotonic() < deadline:
        try:
            mp.describe_channel(Id=channel_id)
        except ClientError as e:
            code_after_delete = e.response["Error"]["Code"]
            message_after_delete = e.response["Error"].get("Message")
            break
        time.sleep(3.0)
    assert code_after_delete == "NotFoundException", (
        f"expected NotFoundException after delete, got {code_after_delete}"
    )
    expected_after = f"channel with id={channel_id} not found"
    assert message_after_delete == expected_after, (
        f"expected message {expected_after!r}, got {message_after_delete!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
