"""disassociate-feed-wrong-resource-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-feed-wrong-resource-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["elementalinference"]


def _subtitling_output(name: str, language: str = "eng") -> dict:
    return {"name": name, "outputConfig": {"subtitling": {"language": language}}, "status": "ENABLED"}


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateFeed with a resourceName that doesn't match the currently associated resource is rejected
    with ValidationException."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    feed_id = ei.create_feed(
        name=name, outputs=[_subtitling_output("sub1")], tags={"sim2real": "audit"}
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))

    correct_name = ctx.unique_name("sim2real-ei-src-")
    ei.associate_feed(id=feed_id, associatedResourceName=correct_name, outputs=[])
    _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "ACTIVE")

    wrong_name = ctx.unique_name("sim2real-ei-src-wrong-")
    code, message = _error_code(lambda: ei.disassociate_feed(id=feed_id, associatedResourceName=wrong_name))
    assert code == "ValidationException", code
    assert message == (
        "You can't disassociate this feed because it isn't associated with the resource you specified. "
        "Specify the correct resource."
    ), message
    got = ei.get_feed(id=feed_id)
    assert got["status"] == "ACTIVE"
    assert got["association"]["associatedResourceName"] == correct_name

    # Positive control: disassociating with the correct name succeeds and archives the feed.
    ei.disassociate_feed(id=feed_id, associatedResourceName=correct_name)
    archived = _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "ARCHIVED")
    assert archived["status"] == "ARCHIVED"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
