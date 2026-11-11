"""get-idle-recommendations-schema."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-idle-recommendations-schema"
GROUP = "data-plane"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """GetIdleRecommendations returns entries scoped to the caller's own account, each
    with a documented finding/resourceType, and (when present) a savingsOpportunity
    object with a currency-denominated estimate.
    """
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    resp = co.get_idle_recommendations(maxResults=25)
    recommendations = resp["idleRecommendations"]
    assert isinstance(recommendations, list), (
        f"idleRecommendations must be a list, got {type(recommendations).__name__}"
    )

    valid_resource_types = {
        "EC2Instance",
        "AutoScalingGroup",
        "EBSVolume",
        "ECSService",
        "RDSDBInstance",
        "NatGateway",
        "DynamoDBTable",
        "ElastiCacheCluster",
        "MemoryDBCluster",
        "DocumentDBCluster",
        "WorkSpaces",
        "SageMakerEndpoint",
    }
    valid_findings = {"Idle", "Unattached", "Unused"}
    for rec in recommendations:
        assert rec["accountId"] == account_id, (
            f"idle recommendation for a foreign account leaked into caller's response: "
            f"expected {account_id}, got {rec.get('accountId')}"
        )
        assert rec["resourceType"] in valid_resource_types, (
            f"undocumented resourceType {rec.get('resourceType')!r}"
        )
        assert rec["finding"] in valid_findings, f"undocumented finding {rec.get('finding')!r}"
        savings = rec.get("savingsOpportunity")
        if savings is not None:
            assert "estimatedMonthlySavings" in savings, (
                f"savingsOpportunity present without estimatedMonthlySavings: {savings!r}"
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
