"""associate-feed-dry-run-does-not-persist."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "associate-feed-dry-run-does-not-persist"
GROUP = "state"
SERVICES = ["elementalinference"]


def _subtitling_output(name: str, language: str = "eng") -> dict:
    return {"name": name, "outputConfig": {"subtitling": {"language": language}}, "status": "ENABLED"}


def _smart_crop_output(name: str) -> dict:
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateFeed with dryRun=True validates the request but persists no state change."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    feed_id = ei.create_feed(name=name, outputs=[_subtitling_output("sub1")])["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))

    resource_name = ctx.unique_name("sim2real-ei-src-")
    ei.associate_feed(
        id=feed_id,
        associatedResourceName=resource_name,
        outputs=[_smart_crop_output("sub2")],
        dryRun=True,
    )

    got = ei.get_feed(id=feed_id)
    assert got["status"] == "AVAILABLE", f"dry run persisted a status change: {got['status']}"
    assert got.get("association") in (None, {}), f"dry run persisted an association: {got.get('association')}"
    assert len(got["outputs"]) == 1, f"dry run persisted an extra output: {got['outputs']}"

    # Positive control, on the identical wiring: the same call without dryRun must actually
    # associate the feed. Without this leg, a target whose AssociateFeed is a no-op regardless
    # of dryRun would score identically to a target that correctly validates-then-discards.
    ei.associate_feed(id=feed_id, associatedResourceName=resource_name, outputs=[_smart_crop_output("sub2")])
    real = _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "ACTIVE")
    assert real["association"]["associatedResourceName"] == resource_name, (
        f"real call did not record the association: {real.get('association')}"
    )
    real_names = {o["name"] for o in real["outputs"]}
    assert real_names == {"sub1", "sub2"}, f"real call did not persist the new output: {real_names}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
