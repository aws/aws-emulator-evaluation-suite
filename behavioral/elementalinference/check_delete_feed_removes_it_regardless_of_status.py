"""delete-feed-removes-it-regardless-of-status."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-feed-removes-it-regardless-of-status"
GROUP = "state"
SERVICES = ["elementalinference"]


def _subtitling_output(name: str, language: str = "eng") -> dict:
    return {"name": name, "outputConfig": {"subtitling": {"language": language}}, "status": "ENABLED"}


def _error_code(fn, within_s=0.0, interval_s=2.0):
    """Call fn() until it raises a ClientError and return its (code, message). A call that still
    SUCCEEDS once within_s has passed raises."""
    deadline = time.monotonic() + within_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _delete_if_present(delete, resource_id):
    """Teardown delete that tolerates a resource the check body already deleted."""
    try:
        delete(id=resource_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteFeed succeeds even while the feed is only AVAILABLE (not archived); the feed then fully disappears and further mutation on it is rejected."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    feed_id = ei.create_feed(name=name, outputs=[_subtitling_output("sub1")])["id"]
    ctx.on_cleanup(lambda: _delete_if_present(ei.delete_feed, feed_id))

    # Positive control: establish the feed is actually AVAILABLE (not merely
    # CREATING, and not yet archived) before proving delete works on it anyway.
    got = _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "AVAILABLE")
    assert got["status"] == "AVAILABLE", f"feed {feed_id} never reached AVAILABLE; last status={got['status']!r}"

    resp = ei.delete_feed(id=feed_id)
    assert resp["id"] == feed_id, f"delete_feed echoed id {resp.get('id')!r}, expected {feed_id!r}"

    code, message = _error_code(lambda: ei.get_feed(id=feed_id), within_s=90.0)
    assert code == "ResourceNotFoundException", f"feed {feed_id} was not fully removed; code={code}"
    assert message == "Resource not found", message

    redelete_code, redelete_message = _error_code(lambda: ei.delete_feed(id=feed_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"deleting the already-deleted feed {feed_id} should also fail not-found, got {redelete_code}"
    )
    assert redelete_message == "Resource not found", redelete_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
