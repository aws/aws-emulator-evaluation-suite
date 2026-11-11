"""update-usage-plan-quota-reflects-change."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-usage-plan-quota-reflects-change"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUsagePlan patches quota/throttle settings, reflected in GetUsagePlan."""
    apigw = ctx.client("apigateway")

    plan_name = ctx.unique_name("sim2real-bh-plan-")
    created = apigw.create_usage_plan(
        name=plan_name,
        quota={"limit": 100, "period": "WEEK"},
        throttle={"rateLimit": 10.0, "burstLimit": 5},
        tags={"sim2real": CHECK},
    )
    plan_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))
    # AWS fills in an implicit "offset": 0 on the quota settings even though we didn't
    # specify one, so compare the fields we actually set rather than the whole dict.
    assert created["quota"]["limit"] == 100, f"expected quota.limit=100, got {created['quota']}"
    assert created["quota"]["period"] == "WEEK", f"expected quota.period=WEEK, got {created['quota']}"
    assert created["throttle"]["burstLimit"] == 5, (
        f"expected throttle.burstLimit=5, got {created['throttle']}"
    )

    updated = apigw.update_usage_plan(
        usagePlanId=plan_id,
        patchOperations=[
            {"op": "replace", "path": "/quota/limit", "value": "200"},
            {"op": "replace", "path": "/throttle/rateLimit", "value": "20.0"},
        ],
    )
    assert updated["name"] == plan_name, "UpdateUsagePlan must not change the name via unrelated ops"
    assert updated["quota"]["limit"] == 200, f"expected quota.limit=200, got {updated['quota']}"
    assert updated["quota"]["period"] == "WEEK", "unrelated quota field must be preserved"
    assert updated["throttle"]["rateLimit"] == 20.0, (
        f"expected throttle.rateLimit=20.0, got {updated['throttle']}"
    )
    assert updated["throttle"]["burstLimit"] == 5, "unrelated throttle field must be preserved"

    fetched = apigw.get_usage_plan(usagePlanId=plan_id)
    assert fetched["quota"]["limit"] == 200, f"expected quota.limit=200, got {fetched['quota']}"
    assert fetched["quota"]["period"] == "WEEK", f"expected quota.period=WEEK, got {fetched['quota']}"
    assert fetched["throttle"]["rateLimit"] == 20.0, (
        f"expected throttle.rateLimit=20.0, got {fetched['throttle']}"
    )
    assert fetched["throttle"]["burstLimit"] == 5, (
        f"expected throttle.burstLimit=5, got {fetched['throttle']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
