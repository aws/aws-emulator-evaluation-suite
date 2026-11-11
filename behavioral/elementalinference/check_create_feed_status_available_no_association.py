"""create-feed-status-available-no-association."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-feed-status-available-no-association"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created feed eventually reaches AVAILABLE, has a data endpoint, and carries no association yet."""
    ei = ctx.client("elementalinference")
    name = ctx.unique_name("sim2real-ei-feed-")
    resp = ei.create_feed(name=name, outputs=[_cropping_output("out1")], tags={"sim2real": "behavioral"})
    feed_id = resp["id"]
    ctx.on_cleanup(lambda: ei.delete_feed(id=feed_id))

    assert resp["status"] in ("AVAILABLE", "CREATING"), f"unexpected initial status {resp['status']}"
    assert resp.get("association") in (None, {}), f"expected no association, got {resp.get('association')}"
    assert len(resp["dataEndpoints"]) >= 1, f"expected at least one data endpoint, got {resp['dataEndpoints']!r}"
    assert len(resp["outputs"]) == 1 and resp["outputs"][0]["name"] == "out1", (
        f"expected exactly one output named 'sub1', got {resp['outputs']!r}"
    )

    got = _poll_until(lambda: ei.get_feed(id=feed_id), lambda r: r["status"] == "AVAILABLE")
    assert got["status"] == "AVAILABLE", f"expected AVAILABLE after polling, got {got['status']!r}"
    assert got.get("association") in (None, {}), f"expected no association, got {got.get('association')!r}"



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
