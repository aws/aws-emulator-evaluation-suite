"""op-contract-describe-aggregate-id-format."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-aggregate-id-format"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAggregateIdFormat reports the long-id status for every
    supported resource type in the Region, aggregated into a single boolean;
    DryRun performs the permission check without returning data."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_aggregate_id_format()
    assert isinstance(resp["UseLongIdsAggregated"], bool), (
        f"expected UseLongIdsAggregated to be a bool, got {resp['UseLongIdsAggregated']!r}"
    )

    statuses = resp["Statuses"]
    assert len(statuses) > 0, "expected at least one resource type in statusSet"
    by_resource = {s["Resource"]: s["UseLongIds"] for s in statuses}
    for expected in ("vpc", "subnet", "instance", "volume", "security-group"):
        assert expected in by_resource, f"expected resource type {expected!r} in {sorted(by_resource)}"
        assert isinstance(by_resource[expected], bool), (
            f"expected UseLongIds for {expected!r} to be a bool, got {by_resource[expected]!r}"
        )

    # the aggregated flag is true iff every individual resource type is true
    assert resp["UseLongIdsAggregated"] == all(by_resource.values()), (
        "UseLongIdsAggregated is inconsistent with the per-resource statuses"
    )

    # error boundary: DryRun surfaces DryRunOperation instead of real data
    code, code_msg = _error(lambda: ec2.describe_aggregate_id_format(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert code_msg == "Request would have succeeded, but DryRun flag is set.", (
        f"expected the exact DryRunOperation message, got {code_msg!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
