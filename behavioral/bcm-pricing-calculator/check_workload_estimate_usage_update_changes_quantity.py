"""workload-estimate-usage-update-changes-quantity."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "workload-estimate-usage-update-changes-quantity"
GROUP = "state"
SERVICES = ["bcm-pricing-calculator"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchUpdateWorkloadEstimateUsage changes the priced quantity for an existing usage line."""
    client = ctx.client("bcm-pricing-calculator")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-we-")

    created = client.create_workload_estimate(name=name, tags={"sim2real": name})
    estimate_id = created["id"]
    ctx.on_cleanup(lambda: _delete_workload_estimate(client, estimate_id))

    create_resp = client.batch_create_workload_estimate_usage(
        workloadEstimateId=estimate_id,
        usage=[
            {
                "serviceCode": "AmazonEC2",
                "usageType": "BoxUsage:t3.micro",
                "operation": "RunInstances",
                "key": "k1",
                "usageAccountId": account_id,
                "amount": 50.0,
            }
        ],
    )
    assert create_resp["errors"] == [], f"batch_create_workload_estimate_usage errors: {create_resp['errors']}"
    usage_id = create_resp["items"][0]["id"]

    _poll_until(
        lambda: client.get_workload_estimate(identifier=estimate_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=120.0,
        interval_s=3.0,
    )
    before = _find_usage_item(client, estimate_id, usage_id)
    quantity_before = before["quantity"]["amount"]
    assert quantity_before == 50.0, f"expected pre-update quantity 50.0, got {quantity_before!r}"

    update_resp = client.batch_update_workload_estimate_usage(
        workloadEstimateId=estimate_id,
        usage=[{"id": usage_id, "amount": 500.0}],
    )
    assert update_resp["errors"] == [], f"batch_update_workload_estimate_usage errors: {update_resp['errors']}"

    _poll_until(
        lambda: client.get_workload_estimate(identifier=estimate_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=120.0,
        interval_s=3.0,
    )
    after = _find_usage_item(client, estimate_id, usage_id)
    quantity_after = after["quantity"]["amount"]

    assert quantity_after == 500.0, f"expected post-update quantity 500.0, got {quantity_after!r} (was {quantity_before!r})"


# ===== helpers =====
def _find_usage_item(client, estimate_id, usage_id):
    items = client.list_workload_estimate_usage(workloadEstimateId=estimate_id)["items"]
    matching = [i for i in items if i["id"] == usage_id]
    assert len(matching) == 1, f"usage item {usage_id} not found in listing"
    return matching[0]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _delete_workload_estimate(client, estimate_id):
    from botocore.exceptions import ClientError

    try:
        client.delete_workload_estimate(identifier=estimate_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
