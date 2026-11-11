"""associate-feed-activates-feed."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "associate-feed-activates-feed"
GROUP = "state"
SERVICES = ["elementalinference"]


def _cropping_output(name: str) -> dict:
    return {"name": name, "outputConfig": {"cropping": {}}, "status": "ENABLED"}


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateFeed drives the documented AVAILABLE -> ACTIVE transition and records the association."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    feed_id = ei.create_feed(
        name=name, outputs=[_cropping_output("out1")], tags={"sim2real": "behav"}
    )["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))

    # Establish the pre-association baseline so the transition is actually proven, not just
    # its destination: a target that marks feeds ACTIVE on creation would otherwise pass.
    before = _poll_until(
        lambda: ei.get_feed(id=feed_id),
        lambda r: r["status"] in ("AVAILABLE", "ACTIVE"),
    )
    assert before["status"] == "AVAILABLE", (
        f"expected the feed to be AVAILABLE (unassociated) before AssociateFeed, got {before['status']!r}"
    )
    assert before.get("association") in (None, {}), (
        f"expected no association before AssociateFeed, got {before.get('association')!r}"
    )

    resource_name = ctx.unique_name("sim2real-ei-src-")
    ei.associate_feed(id=feed_id, associatedResourceName=resource_name, outputs=[])

    got = _poll_until(
        lambda: ei.get_feed(id=feed_id),
        lambda r: r["status"] == "ACTIVE",
    )
    assert got["status"] == "ACTIVE", f"expected ACTIVE after AssociateFeed, got {got['status']!r}"
    assert got["association"]["associatedResourceName"] == resource_name, (
        f"expected association {resource_name!r}, got {got.get('association')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
