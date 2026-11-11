"""update-instance-during-deletion-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-instance-during-deletion-rejected"
GROUP = "overly-permissive"
SERVICES = ["supplychain"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateInstance succeeds while the instance is Active, but once DeleteInstance has put it in
    Deleting the same call fails with ValidationException naming the Active-state requirement, and the
    description stays "while-active"."""
    # AWS Supply Chain is not available in every region (real AWS rejects CreateInstance with
    # ValidationException "... is not supported in us-west-2"); pin to a region where it exists.
    sc = ctx.client("supplychain", region="us-east-1")
    instance_id = _create_active_instance(ctx, sc)

    # positive control: update succeeds while Active
    controlled = sc.update_instance(instanceId=instance_id, instanceDescription="while-active")["instance"]
    assert controlled["instanceDescription"] == "while-active", (
        f"positive control failed: expected 'while-active', got {controlled['instanceDescription']!r}"
    )

    deleted = sc.delete_instance(instanceId=instance_id)["instance"]
    assert deleted["state"] in ("Deleting", "Deleted"), f"unexpected delete state: {deleted}"
    if deleted["state"] == "Deleted":
        raise AssertionError(
            "instance deleted synchronously before the update-during-delete race could be observed"
        )

    error = _error(
        lambda: sc.update_instance(instanceId=instance_id, instanceDescription="while-deleting")
    )
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException while Deleting, got {error}"
    )
    # Real AWS answers either wording for the same request on the same account; both name
    # the Active-state requirement, and nothing else is accepted.
    assert error.get("Message") in (
        "Instance must be in Active state to perform this operation.",
        "Instance must be in Active or Inactive state to perform this operation.",
    ), f"ValidationException message does not name the Active-state requirement: {error}"

    # The asynchronous delete may finish after the refused update; a gone instance carries no
    # description to compare, and a listed one must still read "while-active".
    try:
        still = sc.get_instance(instanceId=instance_id)["instance"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    else:
        assert still["instanceDescription"] == "while-active", (
            f"rejected update mutated the description: {still!r}"
        )


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_active_instance(ctx, sc):
    name = ctx.unique_name("sim2real-sc-")
    instance = sc.create_instance(
        instanceName=name, instanceDescription="sim2real behavioral check", tags={"team": "sim2real"}
    )["instance"]
    instance_id = instance["instanceId"]

    def _cleanup():
        try:
            # An instance already Deleting or Deleted is being removed by AWS; deleting it again is refused.
            if sc.get_instance(instanceId=instance_id)["instance"]["state"] in ("Deleting", "Deleted"):
                return
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
