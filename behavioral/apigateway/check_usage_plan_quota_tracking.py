"""usage-plan-quota-tracking."""
from __future__ import annotations

import datetime
import random
import string

from behavioral_harness import tags

CHECK = "usage-plan-quota-tracking"
GROUP = 'usage-plans'
SERVICES = ['apigateway']


def _unique_token(length=10):
    """Lowercase alphanumeric token (apigateway model/stage names reject hyphens)."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))

def _root_id(ag, api_id):
    for item in ag.get_resources(restApiId=api_id)["items"]:
        if item.get("path") == "/":
            return item["id"]
    raise RuntimeError("root resource not found")

def _create_api(ctx, ag):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: ag.delete_rest_api(restApiId=api_id))
    return api_id

def _quick_stage(ag, api_id, stage_name="prod"):
    """Wire a minimal MOCK method, deployment and stage on api_id; return the deploymentId."""
    resource_id = ag.create_resource(
        restApiId=api_id, parentId=_root_id(ag, api_id), pathPart=f"r{_unique_token()}"
    )["id"]
    ag.put_method(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", authorizationType="NONE"
    )
    ag.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        type="MOCK", requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    ag.put_integration_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    deployment_id = ag.create_deployment(restApiId=api_id)["id"]
    ag.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    return deployment_id


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateUsage on /remaining creates today's GetUsage entry for the key; a second call updates it.
    A never-touched key on the same plan gets no entry, so usage is reported per key.
    """
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag)
    _quick_stage(ag, api_id, "prod")

    plan = ag.create_usage_plan(
        name=ctx.unique_name("plan-"),
        apiStages=[{"apiId": api_id, "stage": "prod"}],
        quota={"limit": 1000, "period": "DAY"},
        tags={"sim2real": CHECK},
    )
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: ag.delete_usage_plan(usagePlanId=plan_id))

    key = ag.create_api_key(name=ctx.unique_name("key-"), enabled=True, tags={"sim2real": CHECK})
    key_id = key["id"]
    ctx.on_cleanup(lambda: ag.delete_api_key(apiKey=key_id))
    ag.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: ag.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    today = datetime.date.today().isoformat()

    ag.update_usage(
        usagePlanId=plan_id,
        keyId=key_id,
        patchOperations=[{"op": "replace", "path": "/remaining", "value": "10"}],
    )
    after = ag.get_usage(usagePlanId=plan_id, startDate=today, endDate=today)
    after_pairs = after.get("items", {}).get(key_id, [])
    assert after_pairs, f"expected UpdateUsage to create a usage entry for {key_id!r} on {today!r}, got {after!r}"
    assert after_pairs[0][1] == 10, (
        f"expected UpdateUsage to set today's remaining quota to 10, got {after_pairs!r}"
    )
    assert len(after_pairs) == 1, f"expected exactly one daily entry for today, got {len(after_pairs)}"

    # A SECOND UpdateUsage on the same day must UPDATE that entry, not append.
    ag.update_usage(
        usagePlanId=plan_id,
        keyId=key_id,
        patchOperations=[{"op": "replace", "path": "/remaining", "value": "5"}],
    )
    after_2 = ag.get_usage(usagePlanId=plan_id, startDate=today, endDate=today)
    after_2_pairs = after_2.get("items", {}).get(key_id, [])
    assert len(after_2_pairs) == 1, (
        f"expected the SECOND same-day UpdateUsage to update the existing entry, not add a new one, "
        f"got {len(after_2_pairs)} entries"
    )
    assert after_2_pairs[0][1] == 5, (
        f"expected the SECOND UpdateUsage to overwrite the remaining quota to 5, got {after_2_pairs!r}"
    )

    # A different, never-touched key under the SAME plan must not be conflated.
    other_key = ag.create_api_key(name=ctx.unique_name("key2-"), enabled=True, tags={"sim2real": CHECK})
    other_key_id = other_key["id"]
    ctx.on_cleanup(lambda: ag.delete_api_key(apiKey=other_key_id))
    ag.create_usage_plan_key(usagePlanId=plan_id, keyId=other_key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: ag.delete_usage_plan_key(usagePlanId=plan_id, keyId=other_key_id))

    combined = ag.get_usage(usagePlanId=plan_id, startDate=today, endDate=today)
    combined_items = combined.get("items", {})
    assert combined_items.get(key_id, [[None, None]])[0][1] == 5, (
        "expected the first key's already-updated remaining quota to persist independently"
    )
    assert other_key_id not in combined_items, (
        f"expected GetUsage to report a usage entry ONLY for the key that actually has one — a "
        f"never-touched key under the same plan must not be conflated with another key's record, "
        f"got items keys={list(combined_items)!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
