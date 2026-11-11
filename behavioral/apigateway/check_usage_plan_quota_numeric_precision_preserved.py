"""usage-plan-quota-numeric-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "usage-plan-quota-numeric-precision-preserved"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Integer quota and fractional throttle values round-trip through CreateUsagePlan/GetUsagePlan exactly."""
    apigw = ctx.client("apigateway")

    plan_name = ctx.unique_name("sim2real-behav-uplan-")
    created = apigw.create_usage_plan(
        name=plan_name,
        quota={"limit": 5000, "offset": 3, "period": "MONTH"},
        throttle={"burstLimit": 200, "rateLimit": 123.456},
        tags={"sim2real": "usage-plan-quota-numeric-precision-preserved"},
    )
    plan_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    fetched = apigw.get_usage_plan(usagePlanId=plan_id)

    assert fetched["quota"]["limit"] == 5000, (
        f"quota.limit drifted: expected 5000, got {fetched['quota']['limit']!r}"
    )
    assert isinstance(fetched["quota"]["limit"], int), (
        f"quota.limit was not returned as an exact integer: {fetched['quota']['limit']!r}"
    )
    assert fetched["quota"]["offset"] == 3, (
        f"quota.offset drifted: expected 3, got {fetched['quota']['offset']!r}"
    )
    assert isinstance(fetched["quota"]["offset"], int), (
        f"quota.offset was not returned as an exact integer: {fetched['quota']['offset']!r}"
    )
    assert fetched["quota"]["period"] == "MONTH", (
        f"quota.period drifted: expected 'MONTH', got {fetched['quota']['period']!r}"
    )
    assert fetched["throttle"]["burstLimit"] == 200, (
        f"throttle.burstLimit drifted: expected 200, got {fetched['throttle']['burstLimit']!r}"
    )
    assert isinstance(fetched["throttle"]["burstLimit"], int), (
        f"throttle.burstLimit was not returned as an exact integer: {fetched['throttle']['burstLimit']!r}"
    )
    assert fetched["throttle"]["rateLimit"] == 123.456, (
        f"rateLimit drifted: {fetched['throttle']['rateLimit']!r} != 123.456"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
