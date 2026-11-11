"""delete-origin-endpoint-removes-effect."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-origin-endpoint-removes-effect"
GROUP = "state"
SERVICES = ["mediapackage"]


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteOriginEndpoint (HTTP 202, may be asynchronous) eventually makes the
    endpoint disappear from both DescribeOriginEndpoint and ListOriginEndpoints."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-delo-")
    mp.create_channel(Id=cid, Tags={"env": "sim2real-test", "purpose": "behavioral-check"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))

    oid = ctx.unique_name("sim2real-mp-oe-")
    mp.create_origin_endpoint(
        Id=oid, ChannelId=cid, HlsPackage={},
        Tags={"env": "sim2real-test", "purpose": "behavioral-check"},
    )

    mp.delete_origin_endpoint(Id=oid)

    deadline = time.monotonic() + 60
    code = message = None
    while time.monotonic() < deadline:
        try:
            mp.describe_origin_endpoint(Id=oid)
        except ClientError as e:
            code, message = e.response["Error"]["Code"], e.response["Error"].get("Message")
            break
        time.sleep(3)
    assert code == "NotFoundException", f"expected deleted endpoint to 404, got {code!r}"
    expected_message = f"originEndpoint with id={oid} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    remaining_ids = [e["Id"] for e in mp.list_origin_endpoints(ChannelId=cid).get("OriginEndpoints", [])]
    assert oid not in remaining_ids, f"expected {oid!r} absent from ListOriginEndpoints, got {remaining_ids!r}"

    redelete_code, redelete_message = _error_code(lambda: mp.delete_origin_endpoint(Id=oid))
    assert redelete_code == "NotFoundException", (
        f"expected a second delete of the dead id to 404, got {redelete_code!r}"
    )
    assert redelete_message == expected_message, (
        f"expected message {expected_message!r}, got {redelete_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
