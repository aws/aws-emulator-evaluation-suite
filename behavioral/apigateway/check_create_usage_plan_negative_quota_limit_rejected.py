"""create-usage-plan-negative-quota-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-usage-plan-negative-quota-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUsagePlan with a negative quota.limit is rejected with BadRequestException, no
    plan is left behind, and an otherwise-identical request with a valid positive limit
    succeeds (positive control, same file)."""
    apigw = ctx.client("apigateway")

    bad_name = ctx.unique_name("sim2real-behav-up-bad-")
    code, message = _error(
        lambda: apigw.create_usage_plan(
            name=bad_name,
            quota={"limit": -5, "period": "DAY"},
            throttle={"rateLimit": 10.0, "burstLimit": 5},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected = "Usage Plan quota limit must be a non-negative numeric"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no usage plan with this name was created.
    names = {p["name"] for p in apigw.get_usage_plans().get("items", [])}
    assert bad_name not in names, f"expected {bad_name!r} absent, found it among {names}"

    # Positive control: a valid positive quota limit is accepted and persisted.
    good_name = ctx.unique_name("sim2real-behav-up-good-")
    created = apigw.create_usage_plan(
        name=good_name,
        quota={"limit": 1000, "period": "DAY"},
        throttle={"rateLimit": 10.0, "burstLimit": 5},
        tags={"sim2real-check": CHECK},
    )
    plan_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    fetched = apigw.get_usage_plan(usagePlanId=plan_id)
    assert fetched["quota"]["limit"] == 1000, f"expected quota.limit=1000, got {fetched['quota']}"
    assert fetched["quota"]["period"] == "DAY", f"expected quota.period='DAY', got {fetched['quota']}"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
