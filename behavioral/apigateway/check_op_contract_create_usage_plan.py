"""op-contract-createUsagePlan."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-createUsagePlan"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUsagePlan echoes throttle/quota on success; referencing a non-existent restApiId/stage
    in apiStages is rejected with NotFoundException and no usage plan is created."""
    apigw = ctx.client("apigateway")

    name = ctx.unique_name("sim2real-behav-plan-")
    created = apigw.create_usage_plan(
        name=name,
        throttle={"rateLimit": 10.0, "burstLimit": 20},
        quota={"limit": 1000, "period": "MONTH"},
        tags={"sim2real": CHECK},
    )
    plan_id = created["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_usage_plan(usagePlanId=plan_id)))
    assert created["name"] == name, f"expected name {name!r}, got {created['name']!r}"
    assert created["throttle"]["burstLimit"] == 20, (
        f"expected echoed burstLimit 20, got {created['throttle'].get('burstLimit')!r}"
    )
    assert created["quota"]["limit"] == 1000 and created["quota"]["period"] == "MONTH", (
        f"expected echoed quota limit=1000/period=MONTH, got {created['quota']!r}"
    )

    fetched = apigw.get_usage_plan(usagePlanId=plan_id)
    assert fetched["throttle"]["rateLimit"] == 10.0, (
        f"expected independent read to show rateLimit 10.0, got {fetched['throttle'].get('rateLimit')!r}"
    )

    orphan_name = ctx.unique_name("sim2real-behav-orphan-plan-")
    err = _client_error(
        lambda: apigw.create_usage_plan(
            name=orphan_name,
            apiStages=[{"apiId": "zzzznotarealapiid", "stage": "nonexistent-stage"}],
        )
    )
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException, got {err.get('Code')!r}"
    assert err.get("Message") == f"Invalid API identifier specified {ctx.account}:zzzznotarealapiid", (
        f"expected the exact NotFound message, got {err.get('Message')!r}"
    )

    orphans = [
        p["id"]
        for page in apigw.get_paginator("get_usage_plans").paginate()
        for p in page["items"]
        if p["name"] == orphan_name
    ]
    assert orphans == [], f"a usage plan was created despite the invalid apiStages reference: {orphans}"
    assert plan_id in {
        p["id"] for page in apigw.get_paginator("get_usage_plans").paginate() for p in page["items"]
    }, f"expected the created plan {plan_id} listed in GetUsagePlans"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
