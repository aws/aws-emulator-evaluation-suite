"""get-auto-scaling-group-recommendations-schema."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-auto-scaling-group-recommendations-schema"
GROUP = "data-plane"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """GetAutoScalingGroupRecommendations returns only the caller's account's groups with documented
    findings; a well-formed nonexistent ARN filter returns no entries and a malformed one fails with
    InvalidParameterValueException and its exact message."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    resp = co.get_auto_scaling_group_recommendations(maxResults=25)
    recommendations = resp.get("autoScalingGroupRecommendations", [])
    assert isinstance(recommendations, list), f"expected a list, got {type(recommendations)!r}"
    assert isinstance(resp.get("errors", []), list), "errors field must be a list"

    valid_findings = {"Underprovisioned", "Overprovisioned", "Optimized", "NotOptimized"}
    for rec in recommendations:
        assert rec["accountId"] == account_id, (
            f"cross-tenant leak: recommendation accountId {rec['accountId']!r} != caller {account_id!r}"
        )
        assert rec["finding"] in valid_findings, f"undocumented finding {rec['finding']!r}"
        expected_prefix = f"arn:aws:autoscaling:{ctx.region}:{account_id}:"
        assert rec["autoScalingGroupArn"].startswith(expected_prefix), (
            f"ARN {rec['autoScalingGroupArn']!r} not scoped to {expected_prefix!r}"
        )

    # Positive control: a syntactically valid ARN for an ASG that does not exist is accepted
    # (200, no fabricated entry) -- isolates ARN *validity* as the one thing the negative below
    # breaks, rather than "any ASG we don't own".
    well_formed_missing_arn = (
        f"arn:aws:autoscaling:{ctx.region}:{account_id}:autoScalingGroup:"
        "00000000-0000-0000-0000-000000000000:autoScalingGroupName/"
        "simparity-audit-nonexistent-asg"
    )
    control_resp = co.get_auto_scaling_group_recommendations(
        autoScalingGroupArns=[well_formed_missing_arn], maxResults=25
    )
    assert control_resp.get("autoScalingGroupRecommendations", []) == [], (
        "a well-formed but nonexistent ASG ARN must not fabricate a recommendation entry"
    )

    code, message = _error(lambda: co.get_auto_scaling_group_recommendations(
        autoScalingGroupArns=["not-a-valid-arn"], maxResults=25
    ))
    assert code == "InvalidParameterValueException", (
        f"malformed ASG ARN must be rejected as InvalidParameterValueException, got {code!r}"
    )
    expected = "Invalid Auto Scaling group ARN."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
