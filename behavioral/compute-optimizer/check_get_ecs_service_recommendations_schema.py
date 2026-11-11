"""get-ecs-service-recommendations-schema."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-ecs-service-recommendations-schema"
GROUP = "data-plane"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """GetECSServiceRecommendations returns entries scoped to the caller's own account,
    each with a documented finding classification and a service ARN in the expected
    ECS ARN format.
    """
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    resp = co.get_ecs_service_recommendations(maxResults=25)
    recommendations = resp["ecsServiceRecommendations"]
    assert isinstance(recommendations, list), f"expected ecsServiceRecommendations to be a list, got {type(recommendations)}"
    errors = resp["errors"]
    assert isinstance(errors, list), f"expected errors to be a list, got {type(errors)}"

    for rec in recommendations:
        assert rec["accountId"] == account_id, f"expected accountId {account_id}, got {rec['accountId']}"
        assert rec["finding"] in ("Optimized", "Underprovisioned", "Overprovisioned"), (
            f"unexpected finding: {rec['finding']}"
        )
        expected_prefix = f"arn:aws:ecs:{ctx.region}:{account_id}:service/"
        assert rec["serviceArn"].startswith(expected_prefix), (
            f"expected serviceArn to start with {expected_prefix}, got {rec['serviceArn']}"
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
