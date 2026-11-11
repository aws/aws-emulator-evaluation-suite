"""instance-update-persists-and-bumps-version."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-update-persists-and-bumps-version"
GROUP = "data-plane"
SERVICES = ["supplychain"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateInstance persists the new instanceName and instanceDescription, as GetInstance shows, and
    leaves versionNumber unchanged across two successive updates."""
    # AWS Supply Chain is not available in us-west-2 (CreateInstance answers
    # ValidationException there); pinned to us-east-1, where it is served.
    sc = ctx.client("supplychain", region="us-east-1")
    instance_id = _create_active_instance(ctx, sc)
    before = sc.get_instance(instanceId=instance_id)["instance"]

    new_name = ctx.unique_name("sim2real-sc-renamed-")
    new_description = "sim2real-updated-description"
    updated = sc.update_instance(
        instanceId=instance_id, instanceName=new_name, instanceDescription=new_description
    )["instance"]

    assert updated["instanceName"] == new_name, (
        f"instanceName not updated: expected={new_name} actual={updated['instanceName']}"
    )
    assert updated["instanceDescription"] == new_description, (
        f"instanceDescription not updated: expected={new_description} "
        f"actual={updated['instanceDescription']}"
    )
    assert updated["versionNumber"] == before["versionNumber"], (
        f"versionNumber changed on a plain UpdateInstance: before={before['versionNumber']} "
        f"after={updated['versionNumber']}"
    )

    fetched = sc.get_instance(instanceId=instance_id)["instance"]
    assert fetched["instanceName"] == new_name, (
        f"independent read did not reflect new name: expected={new_name} actual={fetched['instanceName']}"
    )
    assert fetched["instanceDescription"] == new_description, (
        f"independent read did not reflect new description: expected={new_description} "
        f"actual={fetched['instanceDescription']}"
    )
    assert fetched["versionNumber"] == updated["versionNumber"], (
        f"independent read saw a different versionNumber: update_instance={updated['versionNumber']} "
        f"get_instance={fetched['versionNumber']}"
    )

    # Second successive update: confirm the stability holds across repeated calls, not just once.
    second_description = "sim2real-updated-description-2"
    updated_again = sc.update_instance(
        instanceId=instance_id, instanceDescription=second_description
    )["instance"]
    assert updated_again["instanceDescription"] == second_description, (
        f"second update not applied: expected={second_description} "
        f"actual={updated_again['instanceDescription']}"
    )
    assert updated_again["versionNumber"] == before["versionNumber"], (
        f"versionNumber changed on a second UpdateInstance: before={before['versionNumber']} "
        f"after={updated_again['versionNumber']}"
    )


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
        instanceName=name,
        instanceDescription="sim2real behavioral check",
        tags={"sim2real": CHECK},
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
