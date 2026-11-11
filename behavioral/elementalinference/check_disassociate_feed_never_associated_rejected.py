"""disassociate-feed-never-associated-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-feed-never-associated-rejected"
GROUP = "overly-permissive"
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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateFeed on a feed that is still AVAILABLE (never associated) is rejected with ValidationException."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    feed_id = ei.create_feed(
        name=name, outputs=[_subtitling_output("sub1")], tags={"Environment": "sim2real-behav"}
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))

    some_name = ctx.unique_name("sim2real-ei-src-")
    code, message = _error_code(lambda: ei.disassociate_feed(id=feed_id, associatedResourceName=some_name))
    assert code == "ValidationException", code
    assert message == (
        "You can't disassociate this feed. It has status AVAILABLE which indicate that it's not "
        "currently associated with a resource."
    ), message

    # Effect absent: feed remains AVAILABLE, no association, not archived.
    got = ei.get_feed(id=feed_id)
    assert got["status"] == "AVAILABLE", f"expected AVAILABLE, got {got['status']}"
    assert got.get("association") in (None, {}), f"expected no association, got {got.get('association')!r}"

    # Positive control: associate then disassociate on the same feed succeeds and archives it,
    # proven by an independent terminal read (not just the mutating calls returning without error).
    ei.associate_feed(id=feed_id, associatedResourceName=some_name, outputs=[])
    _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "ACTIVE")

    ei.disassociate_feed(id=feed_id, associatedResourceName=some_name)
    archived = _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "ARCHIVED")
    assert archived["status"] == "ARCHIVED", f"expected ARCHIVED, got {archived['status']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
