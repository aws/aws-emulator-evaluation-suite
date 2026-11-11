"""create-usage-plan-invalid-throttle-rate-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-usage-plan-invalid-throttle-rate-rejected"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUsagePlan with a negative throttle rateLimit is rejected."""
    apigw = ctx.client("apigateway")
    bad_name = ctx.unique_name("sim2real-behav-apigw-plan-bad-")

    code, message = _error(
        lambda: apigw.create_usage_plan(
            name=bad_name, throttle={"rateLimit": -5.0, "burstLimit": 10}
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    expected = "Usage Plan throttle rate limit and burst limit must be numeric and greater than zero"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # (b) effect absent: no usage plan with that name exists.
    plans = _list_all_usage_plans(apigw)
    assert not any(p["name"] == bad_name for p in plans), "a usage plan was created despite rejection"

    # (c) positive control: a valid non-negative rateLimit succeeds.
    good_name = ctx.unique_name("sim2real-behav-apigw-plan-good-")
    plan = apigw.create_usage_plan(
        name=good_name,
        throttle={"rateLimit": 10.0, "burstLimit": 20},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan["id"]))
    assert plan["throttle"]["rateLimit"] == 10.0, (
        f"expected create response rateLimit 10.0, got {plan['throttle'].get('rateLimit')}"
    )

    # terminal read: independent of the mutating call, at the destination.
    fetched = apigw.get_usage_plan(usagePlanId=plan["id"])
    assert fetched["throttle"]["rateLimit"] == 10.0, (
        f"expected persisted rateLimit 10.0, got {fetched['throttle'].get('rateLimit')}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _list_all_usage_plans(apigw):
    items = []
    resp = apigw.get_usage_plans(limit=500)
    items.extend(resp.get("items", []))
    while resp.get("position"):
        resp = apigw.get_usage_plans(limit=500, position=resp["position"])
        items.extend(resp.get("items", []))
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
