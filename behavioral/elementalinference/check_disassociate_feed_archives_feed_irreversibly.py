"""disassociate-feed-archives-feed-irreversibly."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-feed-archives-feed-irreversibly"
GROUP = "state"
SERVICES = ["elementalinference"]


def _subtitling_output(name: str, language: str = "eng") -> dict:
    return {"name": name, "outputConfig": {"subtitling": {"language": language}}, "status": "ENABLED"}


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateFeed indirectly and irreversibly archives the feed (ACTIVE -> ARCHIVED, one-way)."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    feed_id = ei.create_feed(
        name=name, outputs=[_subtitling_output("sub1")], tags={"Environment": "sim2real-behav"}
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))

    resource_name = ctx.unique_name("sim2real-ei-src-")
    ei.associate_feed(id=feed_id, associatedResourceName=resource_name, outputs=[])
    _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "ACTIVE")

    ei.disassociate_feed(id=feed_id, associatedResourceName=resource_name)
    got = _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "ARCHIVED")
    assert got["status"] == "ARCHIVED", f"expected ARCHIVED, got {got['status']}"

    # Archiving is one-way: you cannot reassociate an archived feed.
    code, message = _error_code(
        lambda: ei.associate_feed(id=feed_id, associatedResourceName=resource_name, outputs=[])
    )
    assert code == "ValidationException", code
    assert message == (
        "You can't update a feed that has ARCHIVED status. If you need this feed, you should create it again."
    ), message

    # Effect absent: the rejected reassociation attempt did not move the feed off ARCHIVED.
    still_archived = ei.get_feed(id=feed_id)
    assert still_archived["status"] == "ARCHIVED", (
        f"expected ARCHIVED to survive the rejected reassociation, got {still_archived['status']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
