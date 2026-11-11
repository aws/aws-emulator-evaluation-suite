"""workload-estimate-usage-delete-removes-item."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "workload-estimate-usage-delete-removes-item"
GROUP = "state"
SERVICES = ["bcm-pricing-calculator"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDeleteWorkloadEstimateUsage removes a usage line so it no longer appears in the
    listing, and a subsequent mutation on the deleted usage id is itself rejected."""
    client = ctx.client("bcm-pricing-calculator")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-we-")
    resource_tags = {"sim2real-owner": "workload-estimate-usage-delete-removes-item"}

    created = client.create_workload_estimate(name=name, tags=resource_tags)
    estimate_id = created["id"]
    ctx.on_cleanup(lambda: _delete_workload_estimate(client, estimate_id))

    create_resp = client.batch_create_workload_estimate_usage(
        workloadEstimateId=estimate_id,
        usage=[
            {
                "serviceCode": "AmazonS3",
                "usageType": "TimedStorage-ByteHrs",
                "operation": "StandardStorage",
                "key": "k1",
                "usageAccountId": account_id,
                "amount": 10.0,
            }
        ],
    )
    assert create_resp["errors"] == [], f"expected no create errors, got {create_resp['errors']!r}"
    usage_id = create_resp["items"][0]["id"]

    before_ids = {i["id"] for i in client.list_workload_estimate_usage(workloadEstimateId=estimate_id)["items"]}
    assert usage_id in before_ids, f"expected {usage_id!r} in pre-delete listing {before_ids!r}"

    delete_resp = client.batch_delete_workload_estimate_usage(workloadEstimateId=estimate_id, ids=[usage_id])
    assert delete_resp["errors"] == [], f"expected no delete errors, got {delete_resp['errors']!r}"

    after_ids = {i["id"] for i in client.list_workload_estimate_usage(workloadEstimateId=estimate_id)["items"]}
    assert usage_id not in after_ids, f"expected {usage_id!r} absent from post-delete listing {after_ids!r}"

    # A mutation on the dead usage id must fail too, not just the read.
    update_resp = client.batch_update_workload_estimate_usage(
        workloadEstimateId=estimate_id,
        usage=[{"id": usage_id, "amount": 999.0}],
    )
    assert update_resp["items"] == [], f"expected no updated items for a deleted usage id, got {update_resp['items']!r}"
    update_errors = update_resp["errors"]
    assert len(update_errors) == 1, f"expected exactly one update error, got {update_errors!r}"
    assert update_errors[0]["id"] == usage_id, f"expected error keyed on {usage_id!r}, got {update_errors[0]!r}"
    assert update_errors[0]["errorCode"] == "NOT_FOUND", (
        f"expected NOT_FOUND updating a deleted usage id, got {update_errors[0]['errorCode']!r}"
    )


# ===== helpers =====
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
