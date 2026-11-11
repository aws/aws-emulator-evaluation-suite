"""instance-delete-lifecycle-to-deleted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-delete-lifecycle-to-deleted"
GROUP = "state-machine"
SERVICES = ["supplychain"]

# AWS Supply Chain is not available in us-west-2 (real AWS rejects CreateInstance there
# with ValidationException); the control plane only exists in us-east-1.
_SC_REGION = "us-east-1"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteInstance returns the instance in state Deleting or Deleted; GetInstance then eventually fails
    with ResourceNotFoundException, and a second DeleteInstance fails with "Instance not found."
    (ResourceNotFoundException)."""
    sc = ctx.client("supplychain", region=_SC_REGION)
    instance_id = _create_active_instance(ctx, sc)

    deleted = sc.delete_instance(instanceId=instance_id)["instance"]
    assert deleted["state"] in ("Deleting", "Deleted"), f"unexpected delete state: {deleted}"

    _poll_until_not_found(
        lambda: sc.get_instance(instanceId=instance_id)["instance"],
        timeout_s=1200.0,
        interval_s=15.0,
    )

    code, message = _error(lambda: sc.delete_instance(instanceId=instance_id))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException re-deleting an already-deleted instance, got {code}"
    )
    assert message == "Instance not found.", f"expected 'Instance not found.', got {message!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _poll_until_not_found(probe, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        try:
            last_state = probe()["state"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(
        "instance was never hard-deleted -- GetInstance did not raise "
        f"ResourceNotFoundException within {timeout_s}s; last observed state={last_state!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_active_instance(ctx, sc):
    name = ctx.unique_name("sim2real-sc-")
    instance = sc.create_instance(
        instanceName=name,
        instanceDescription="sim2real behavioral check",
        tags={"team": "sim2real"},
    )["instance"]
    instance_id = instance["instanceId"]

    def _cleanup():
        try:
            sc.delete_instance(instanceId=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    result = _poll_until(
        lambda: sc.get_instance(instanceId=instance_id)["instance"],
        lambda inst: inst["state"] in ("Active", "CreateFailed"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if result["state"] != "Active":
        raise AssertionError(f"instance did not reach Active state: {result}")
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
