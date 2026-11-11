"""update-usage-plan-and-list-plans."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-usage-plan-and-list-plans"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUsagePlan patches throttle/quota settings and GetUsagePlans lists
    the plan with the updated values; deleting it then removes it from both
    GetUsagePlan and GetUsagePlans."""
    apigw = ctx.client("apigateway")
    plan_name = ctx.unique_name("sim2real-plan-")
    plan_id = apigw.create_usage_plan(
        name=plan_name,
        throttle={"rateLimit": 10.0, "burstLimit": 5},
        quota={"limit": 1000, "period": "DAY"},
        tags={"sim2real": plan_name},
    )["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_usage_plan(usagePlanId=plan_id)))

    apigw.update_usage_plan(
        usagePlanId=plan_id,
        patchOperations=[
            {"op": "replace", "path": "/quota/limit", "value": "2000"},
            {"op": "replace", "path": "/quota/period", "value": "WEEK"},
            {"op": "replace", "path": "/throttle/rateLimit", "value": "20"},
            {"op": "replace", "path": "/throttle/burstLimit", "value": "8"},
        ],
    )

    plans = _all_usage_plans(apigw)
    by_id = {p["id"]: p for p in plans}
    assert plan_id in by_id, f"expected {plan_id} listed in GetUsagePlans"
    plan = by_id[plan_id]
    assert plan["quota"]["limit"] == 2000, plan["quota"]
    assert plan["quota"]["period"] == "WEEK", plan["quota"]
    assert plan["throttle"]["rateLimit"] == 20.0, plan["throttle"]
    assert plan["throttle"]["burstLimit"] == 8, plan["throttle"]

    apigw.delete_usage_plan(usagePlanId=plan_id)
    err = _client_error(lambda: apigw.get_usage_plan(usagePlanId=plan_id))
    assert (err.get("Code"), err.get("Message")) == ('NotFoundException', 'Invalid Usage Plan ID specified'), (
        f"expected NotFoundException after delete, got {err!r}"
    )
    remaining_ids = {p["id"] for p in _all_usage_plans(apigw)}
    assert plan_id not in remaining_ids, "deleted usage plan still listed in GetUsagePlans"


def _all_usage_plans(apigw) -> list:
    """Every usage plan GetUsagePlans lists, across all pages."""
    return [p for page in apigw.get_paginator("get_usage_plans").paginate() for p in page["items"]]


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
