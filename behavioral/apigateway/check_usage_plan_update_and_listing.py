"""usage-plan-update-and-listing."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "usage-plan-update-and-listing"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUsagePlan patches throttle/quota, the change is reflected in GetUsagePlans,
    and the untouched quota period survives the patch unchanged."""
    apigw = ctx.client("apigateway")

    created = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-plan-"),
        throttle={"burstLimit": 5, "rateLimit": 10.0},
        quota={"limit": 1000, "period": "MONTH"},
        tags={"sim2real": "usage-plan-update-and-listing"},
    )
    plan_id = created["id"]
    assert created["throttle"]["rateLimit"] == 10.0, created["throttle"]
    assert created["quota"]["limit"] == 1000, created["quota"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_usage_plan(usagePlanId=plan_id)))

    updated = apigw.update_usage_plan(
        usagePlanId=plan_id,
        patchOperations=[
            {"op": "replace", "path": "/throttle/rateLimit", "value": "20.0"},
            {"op": "replace", "path": "/throttle/burstLimit", "value": "8"},
            {"op": "replace", "path": "/quota/limit", "value": "2000"},
        ],
    )
    assert updated["throttle"]["rateLimit"] == 20.0, updated["throttle"]
    assert updated["throttle"]["burstLimit"] == 8, updated["throttle"]
    assert updated["quota"]["limit"] == 2000, updated["quota"]
    assert updated["quota"]["period"] == "MONTH", (
        f"unpatched quota period must be preserved, got {updated['quota']}"
    )

    listed = apigw.get_usage_plans(limit=500)["items"]
    match = next((p for p in listed if p["id"] == plan_id), None)
    assert match is not None, "usage plan missing from GetUsagePlans"
    assert match["throttle"]["rateLimit"] == 20.0, match["throttle"]
    assert match["throttle"]["burstLimit"] == 8, match["throttle"]
    assert match["quota"]["limit"] == 2000, match["quota"]
    assert match["quota"]["period"] == "MONTH", (
        f"unpatched quota period must be preserved in GetUsagePlans, got {match['quota']}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
