"""batch-create-workload-estimate-usage-exceeds-max-entries-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-create-workload-estimate-usage-exceeds-max-entries-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-pricing-calculator"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A batch of 26 usage entries (over the 25-entry max) is rejected wholesale, with no partial writes."""
    client = ctx.client("bcm-pricing-calculator")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-we-")

    estimate_id = client.create_workload_estimate(name=name)["id"]
    ctx.on_cleanup(lambda: _delete_workload_estimate(client, estimate_id))

    def _entry(i):
        return {
            "serviceCode": "AmazonEC2",
            "usageType": "BoxUsage:t3.micro",
            "operation": "RunInstances",
            "key": f"k{i}",
            "usageAccountId": account_id,
            "amount": 1.0,
        }

    too_many = [_entry(i) for i in range(26)]
    code, message = _error_code_and_message(
        lambda: client.batch_create_workload_estimate_usage(workloadEstimateId=estimate_id, usage=too_many)
    )
    assert code == "ValidationException", f"expected ValidationException for a 26-entry batch, got {code!r}"
    expected_message = (
        "1 validation error detected: Value at 'usage' failed to satisfy constraint: "
        "Member must have length less than or equal to 25"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: nothing from the rejected batch was written.
    listed = client.list_workload_estimate_usage(workloadEstimateId=estimate_id)["items"]
    assert listed == [], f"expected no usage items after the rejected batch, found {listed!r}"

    # Positive control: a single valid entry from the same batch succeeds on its own.
    ok_resp = client.batch_create_workload_estimate_usage(workloadEstimateId=estimate_id, usage=[_entry(0)])
    assert ok_resp["errors"] == [], f"expected no per-item errors, got {ok_resp['errors']!r}"
    assert len(ok_resp["items"]) == 1, f"expected exactly 1 item created, got {len(ok_resp['items'])}"
    usage_id = ok_resp["items"][0]["id"]

    # Terminal read: independent of the write that created it, at the destination.
    listed_after = client.list_workload_estimate_usage(workloadEstimateId=estimate_id)["items"]
    matching = [i for i in listed_after if i["id"] == usage_id]
    assert len(matching) == 1, f"expected the accepted entry visible via list, found {matching!r} among {listed_after!r}"
    assert matching[0]["serviceCode"] == "AmazonEC2", f"expected serviceCode AmazonEC2, got {matching[0].get('serviceCode')!r}"
    assert matching[0]["usageType"] == "BoxUsage:t3.micro", f"expected usageType BoxUsage:t3.micro, got {matching[0].get('usageType')!r}"


# ===== helpers =====
def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the batch to be rejected, but it succeeded with {result!r}")


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
