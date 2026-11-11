"""workload-estimate-usage-add-reaches-terminal-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "workload-estimate-usage-add-reaches-terminal-state"
GROUP = "state"
SERVICES = ["bcm-pricing-calculator"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Adding modeled usage to a WorkloadEstimate is priced and the estimate leaves UPDATING."""
    client = ctx.client("bcm-pricing-calculator")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-we-")

    created = client.create_workload_estimate(name=name)
    estimate_id = created["id"]
    ctx.on_cleanup(lambda: _delete_workload_estimate(client, estimate_id))

    resp = client.batch_create_workload_estimate_usage(
        workloadEstimateId=estimate_id,
        usage=[
            {
                "serviceCode": "AmazonEC2",
                "usageType": "BoxUsage:t3.micro",
                "operation": "RunInstances",
                "key": "k1",
                "usageAccountId": account_id,
                "amount": 100.0,
            }
        ],
    )
    assert resp["errors"] == [], f"expected no batch-create errors, got {resp['errors']!r}"
    assert len(resp["items"]) == 1, f"expected 1 created item, got {len(resp['items'])}"
    usage_id = resp["items"][0]["id"]

    final = _poll_until(
        lambda: client.get_workload_estimate(identifier=estimate_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=120.0,
        interval_s=3.0,
    )
    # A well-formed, priced EC2 usage line settles VALID; INVALID/ACTION_NEEDED are for unpriceable
    # or actionable usage, not this one.
    assert final["status"] == "VALID", f"expected VALID after pricing settles, got {final['status']!r}"
    assert final["totalCost"] > 0.0, f"expected nonzero total cost after pricing usage, got {final['totalCost']!r}"

    listed = client.list_workload_estimate_usage(workloadEstimateId=estimate_id)["items"]
    matching = [i for i in listed if i["id"] == usage_id]
    assert len(matching) == 1, f"expected exactly 1 usage item with id {usage_id}, found {len(matching)}"
    item = matching[0]
    assert item["serviceCode"] == "AmazonEC2", f"expected serviceCode AmazonEC2, got {item['serviceCode']!r}"
    assert item["usageType"] == "BoxUsage:t3.micro", f"expected usageType BoxUsage:t3.micro, got {item['usageType']!r}"
    assert item["operation"] == "RunInstances", f"expected operation RunInstances, got {item['operation']!r}"
    assert item["status"] == "VALID", f"expected usage item cost status VALID, got {item['status']!r}"
    assert item["cost"] > 0.0, f"expected the priced usage line to carry a nonzero cost, got {item['cost']!r}"


# ===== helpers =====
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
