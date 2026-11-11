"""usage-plan-quota-large-numeric-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "usage-plan-quota-large-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUsagePlan with a large integer quota limit; GetUsagePlan must return the
    exact same integer -- no float round-tripping through the JSON layer that would
    drift a large value (e.g. via double-precision truncation)."""
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-usageplan-")
    large_limit = 1234567891

    created = apigw.create_usage_plan(
        name=name,
        quota={"limit": large_limit, "period": "MONTH"},
        tags={"sim2real": "usage-plan-quota-large-numeric-precision-preserved"},
    )
    plan_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    assert created["quota"]["limit"] == large_limit, (
        f"create response quota limit drifted: sent={large_limit} got={created['quota']['limit']!r}"
    )
    assert isinstance(created["quota"]["limit"], int), (
        f"create response quota limit was not an exact integer: {created['quota']['limit']!r}"
    )

    fetched = apigw.get_usage_plan(usagePlanId=plan_id)
    assert fetched["quota"]["limit"] == large_limit, (
        f"quota limit drifted: sent={large_limit} got={fetched['quota']['limit']!r}"
    )
    assert isinstance(fetched["quota"]["limit"], int), (
        f"quota limit was not returned as an exact integer: {fetched['quota']['limit']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
