"""get-recommendation-summaries-matches-caller-account."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-recommendation-summaries-matches-caller-account"
GROUP = "data-plane"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """GetRecommendationSummaries returns at least one summary, every one with the caller's accountId and
    a documented recommendationResourceType."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    resp = co.get_recommendation_summaries()
    summaries = resp["recommendationSummaries"]
    assert isinstance(summaries, list), (
        f"expected recommendationSummaries to be a list, got {type(summaries)!r}"
    )
    assert len(summaries) > 0, (
        "expected at least one recommendation summary for an opted-in account: real AWS "
        "returns a summary entry per tracked resource type even with zero analyzed "
        f"resources, got an empty list from resp={resp!r}"
    )

    valid_resource_types = {
        "Ec2Instance",
        "AutoScalingGroup",
        "EbsVolume",
        "LambdaFunction",
        "EcsService",
        "License",
        "RdsDBInstance",
        "RdsDBInstanceStorage",
        "AuroraDBClusterStorage",
        "NatGateway",
        "DynamoDBTable",
        "ElastiCacheCluster",
        "MemoryDBCluster",
        "DocumentDBCluster",
        "WorkSpaces",
        "SageMakerEndpoint",
    }
    for summary in summaries:
        assert summary["accountId"] == account_id, (
            f"expected summary accountId {account_id!r}, got "
            f"{summary.get('accountId')!r} (cross-account leakage)"
        )
        resource_type = summary["recommendationResourceType"]
        assert resource_type in valid_resource_types, (
            f"recommendationResourceType {resource_type!r} is not a documented resource type"
        )


def _ensure_opted_in(co, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    status = co.get_enrollment_status().get("status")
    if status != "Active":
        co.update_enrollment_status(status="Active")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = co.get_enrollment_status().get("status")
        if status == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"account never reached Active enrollment status, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
