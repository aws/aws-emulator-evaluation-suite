"""delete-origin-endpoint-removes-it-from-list."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-origin-endpoint-removes-it-from-list"
GROUP = "state"
SERVICES = ["mediapackage"]


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteOriginEndpoint, DescribeOriginEndpoint and UpdateOriginEndpoint on the id both fail
    NotFoundException with the exact message and the endpoint leaves ListOriginEndpoints."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-chan-")
    mp.create_channel(Id=channel_id)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    endpoint_id = ctx.unique_name("sim2real-mp-ep-")
    mp.create_origin_endpoint(
        Id=endpoint_id, ChannelId=channel_id, HlsPackage={"SegmentDurationSeconds": 6}
    )

    mp.delete_origin_endpoint(Id=endpoint_id)

    deadline = time.monotonic() + 60
    code = message = None
    while time.monotonic() < deadline:
        try:
            mp.describe_origin_endpoint(Id=endpoint_id)
        except ClientError as err:
            code, message = err.response["Error"]["Code"], err.response["Error"].get("Message")
            break
        time.sleep(2)
    assert code == "NotFoundException", (
        f"expected deleted endpoint to 404 on DescribeOriginEndpoint within 60s, got {code!r}"
    )
    expected_message = f"originEndpoint with id={endpoint_id} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    listed = mp.list_origin_endpoints(ChannelId=channel_id)
    remaining = {ep["Id"] for ep in listed["OriginEndpoints"]}
    assert endpoint_id not in remaining, (
        f"deleted endpoint {endpoint_id!r} still present in ListOriginEndpoints: {sorted(remaining)!r}"
    )

    update_code, update_message = _error_code(lambda: mp.update_origin_endpoint(Id=endpoint_id))
    assert update_code == "NotFoundException", (
        f"expected UpdateOriginEndpoint against a deleted id to be rejected NotFoundException, got {update_code!r}"
    )
    assert update_message == expected_message, (
        f"expected message {expected_message!r}, got {update_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
