"""usage-plan-invalid-quota-offset-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "usage-plan-invalid-quota-offset-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUsagePlan rejects a quota offset >= limit, leaving no plan created, while a valid plan still succeeds."""
    apigw = ctx.client("apigateway")

    # Positive control: a well-formed usage plan is created and readable exactly as sent.
    positive_name = ctx.unique_name("sim2real-behav-uplan-ctrl-")
    positive = apigw.create_usage_plan(
        name=positive_name,
        quota={"limit": 1000, "offset": 0, "period": "MONTH"},
        throttle={"burstLimit": 10, "rateLimit": 5.0},
    )
    plan_id = positive["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    got_positive = apigw.get_usage_plan(usagePlanId=plan_id)
    assert got_positive["name"] == positive_name, (
        f"expected the read-back name to be {positive_name!r}, got {got_positive['name']!r}"
    )
    assert got_positive["quota"]["limit"] == 1000, (
        f"expected the read-back quota limit to be 1000, got {got_positive['quota']['limit']!r}"
    )

    # Negative: quota.offset must be strictly less than quota.limit.
    negative_name = ctx.unique_name("sim2real-behav-uplan-neg-")
    error = _client_error(
        lambda: apigw.create_usage_plan(
            name=negative_name,
            quota={"limit": 50, "offset": 50, "period": "DAY"},
            throttle={"burstLimit": 10, "rateLimit": 5.0},
        )
    )
    expected = ("BadRequestException", "Usage Plan quota offset must be zero in the DAY period")
    assert (error.get("Code"), error.get("Message")) == expected, (
        f"expected {expected!r} for a nonzero DAY-period offset, got {error!r}"
    )

    # Effect absent: no usage plan with the rejected name was ever created.
    paginator_items: list[dict[str, Any]] = []
    position = None
    while True:
        kwargs = {"limit": 500}
        if position:
            kwargs["position"] = position
        page = apigw.get_usage_plans(**kwargs)
        paginator_items.extend(page.get("items", []))
        position = page.get("position")
        if not position:
            break
    assert not any(p["name"] == negative_name for p in paginator_items), (
        "a usage plan was created despite the rejected quota offset/limit combination"
    )

    # Positive control is still intact and untouched by the failed negative call.
    got_positive_again = apigw.get_usage_plan(usagePlanId=plan_id)
    assert got_positive_again["name"] == positive_name, (
        f"expected the positive control's name to remain {positive_name!r}, "
        f"got {got_positive_again['name']!r}"
    )
    assert got_positive_again["quota"]["limit"] == 1000, (
        f"expected the positive control's quota limit to remain 1000, "
        f"got {got_positive_again['quota']['limit']!r}"
    )


def _client_error(fn: Callable[[], Any]) -> dict[str, Any]:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
