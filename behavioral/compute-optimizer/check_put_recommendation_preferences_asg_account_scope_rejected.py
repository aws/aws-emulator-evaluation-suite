"""put-recommendation-preferences-asg-account-scope-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-recommendation-preferences-asg-account-scope-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """PutRecommendationPreferences for AutoScalingGroup at AccountId scope fails with
    InvalidParameterValueException and its exact message and stores no lookBackPeriod there, while the
    same Ec2Instance preference is stored as DAYS_32."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    asg_scope = {"name": "AccountId", "value": account_id}

    code, message = _error(
        lambda: co.put_recommendation_preferences(
            resourceType="AutoScalingGroup", scope=asg_scope, lookBackPeriod="DAYS_32"
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for AccountId-scoped AutoScalingGroup "
        f"preferences, got {code!r}"
    )
    expected = (
        "You cannot create a recommendation preference for an Auto Scaling Group with "
        'the "Organization" or "AccountId" scope name. Specify "ResourceArn" as the '
        "scope name, the Auto Scaling group ARN ID as the scope value, and try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no AccountId-scoped AutoScalingGroup preference entry was created
    detail = _find_detail(co, "AutoScalingGroup", asg_scope)
    assert detail is None or detail.get("lookBackPeriod") is None, (
        f"expected no AccountId-scoped AutoScalingGroup lookBackPeriod entry after the "
        f"rejected put, got {detail!r}"
    )

    # positive control: the same operation succeeds for a resourceType that DOES
    # support AccountId-scoped preferences (Ec2Instance)
    ec2_scope = {"name": "AccountId", "value": account_id}
    co.put_recommendation_preferences(
        resourceType="Ec2Instance", scope=ec2_scope, lookBackPeriod="DAYS_32"
    )
    ctx.on_cleanup(
        lambda: co.delete_recommendation_preferences(
            resourceType="Ec2Instance", scope=ec2_scope, recommendationPreferenceNames=["LookBackPeriodPreference"]
        )
    )
    ec2_detail = _find_detail(co, "Ec2Instance", ec2_scope)
    assert ec2_detail is not None, (
        "expected an AccountId-scoped Ec2Instance preference entry after "
        "put_recommendation_preferences succeeded, got none"
    )
    assert ec2_detail["lookBackPeriod"] == "DAYS_32", (
        f"expected lookBackPeriod=DAYS_32 for the AccountId-scoped Ec2Instance entry, "
        f"got {ec2_detail.get('lookBackPeriod')!r}"
    )


def _find_detail(co, resource_type, scope):
    resp = co.get_recommendation_preferences(resourceType=resource_type, scope=scope)
    for detail in resp.get("recommendationPreferencesDetails", []):
        if detail.get("scope", {}).get("name") == scope["name"] and detail.get("scope", {}).get("value") == scope["value"]:
            return detail
    return None


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED and returned {result!r}")


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
