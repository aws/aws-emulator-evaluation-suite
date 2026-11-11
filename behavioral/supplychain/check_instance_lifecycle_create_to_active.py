"""instance-lifecycle-create-to-active."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-lifecycle-create-to-active"
GROUP = "state-machine"
SERVICES = ["supplychain"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInstance returns Initializing immediately and the instance transitions to Active."""
    # AWS Supply Chain's control plane does not serve us-west-2 (real AWS returns
    # ValidationException: "Amazon Connect Decisions is not supported in us-west-2"), so the
    # client is pinned to us-east-1.
    sc = ctx.client("supplychain", region="us-east-1")
    name = ctx.unique_name("sim2real-sc-")
    created = sc.create_instance(
        instanceName=name,
        instanceDescription="sim2real behavioral check",
        tags={"sim2real": "instance-lifecycle-create-to-active"},
    )["instance"]
    instance_id = created["instanceId"]
    ctx.on_cleanup(lambda: _best_effort_delete(sc, instance_id))

    # CreateInstance is documented as asynchronous: it must return the instance immediately
    # in the Initializing state, before any polling.
    assert created["state"] == "Initializing", f"unexpected initial state: {created['state']}"

    final = _poll_until(
        lambda: sc.get_instance(instanceId=instance_id)["instance"],
        lambda inst: inst["state"] in ("Active", "CreateFailed"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    assert final["state"] == "Active", f"instance did not reach Active: {final}"
    assert final["instanceId"] == instance_id
    assert final["versionNumber"] is not None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _best_effort_delete(sc, instance_id):
    try:
        sc.delete_instance(instanceId=instance_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
