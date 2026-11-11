"""create-usage-plan-negative-throttle-rate-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-usage-plan-negative-throttle-rate-rejected"
GROUP = "negative-classes"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUsagePlan with a negative throttle rateLimit is rejected as out-of-range and no
    usage plan is created, while a non-negative rateLimit on the same call shape succeeds."""
    apigw = ctx.client("apigateway")

    bad_name = ctx.unique_name("sim2real-behav-plan-bad-")
    code, message = _error(
        lambda: apigw.create_usage_plan(
            name=bad_name,
            throttle={"rateLimit": -5.0, "burstLimit": 5},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected = "Usage Plan throttle rate limit and burst limit must be numeric and greater than zero"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect-absent: no usage plan with that name was created.
    plans = apigw.get_usage_plans(limit=500).get("items", [])
    assert not any(p.get("name") == bad_name for p in plans), "a usage plan was created despite the negative rate"

    # positive control: identical call shape with a valid non-negative rateLimit succeeds.
    good_name = ctx.unique_name("sim2real-behav-plan-ok-")
    created = apigw.create_usage_plan(
        name=good_name,
        throttle={"rateLimit": 10.0, "burstLimit": 5},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=created["id"]))
    assert created["name"] == good_name
    assert created["throttle"]["rateLimit"] == 10.0

    fetched = apigw.get_usage_plan(usagePlanId=created["id"])
    assert fetched["throttle"]["rateLimit"] == 10.0


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
