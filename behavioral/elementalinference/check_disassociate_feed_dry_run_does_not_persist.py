"""disassociate-feed-dry-run-does-not-persist."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "disassociate-feed-dry-run-does-not-persist"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateFeed with dryRun=True validates the request without archiving the feed or clearing the association."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    feed_id = ei.create_feed(
        name=name, outputs=[_subtitling_output("sub1")], tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))

    resource_name = ctx.unique_name("sim2real-ei-src-")
    ei.associate_feed(id=feed_id, associatedResourceName=resource_name, outputs=[])
    _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "ACTIVE")

    ei.disassociate_feed(id=feed_id, associatedResourceName=resource_name, dryRun=True)

    got = ei.get_feed(id=feed_id)
    assert got["status"] == "ACTIVE", f"dry run archived the feed: {got['status']}"
    assert got["association"]["associatedResourceName"] == resource_name

    # Positive control on the same wiring: without dryRun, the identical call does archive
    # the feed. Without this leg, a target that never implements disassociate at all would
    # pass the assertions above just as well as one that correctly honors dryRun.
    ei.disassociate_feed(id=feed_id, associatedResourceName=resource_name)
    archived = _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "ARCHIVED")
    assert archived["status"] == "ARCHIVED", f"real disassociate did not archive: {archived['status']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
