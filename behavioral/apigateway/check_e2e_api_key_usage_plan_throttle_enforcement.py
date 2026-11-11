"""e2e-api-key-usage-plan-throttle-enforcement."""
from __future__ import annotations

import datetime
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "e2e-api-key-usage-plan-throttle-enforcement"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An API key in a low-throttle usage plan throttles rapid calls to the deployed stage (some
    200s, some 429s), and GetUsage returns a well-formed daily usage record for that key
    (the count lags live traffic, so its value is not asserted)."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-throttle-"),
        tags={"sim2real": "api-key-usage-plan-throttle-enforcement"},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: _safe_delete_rest_api(apigw, api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="limited")
    resource_id = resource["id"]

    apigw.put_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        authorizationType="NONE",
        apiKeyRequired=True,
    )
    apigw.put_method_response(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", statusCode="200"
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "ok"}'},
    )

    deployment = apigw.create_deployment(restApiId=api_id)
    stage_name = "prod"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment["id"])

    key = apigw.create_api_key(
        name=ctx.unique_name("sim2real-key-"),
        enabled=True,
        tags={"sim2real": "api-key-usage-plan-throttle-enforcement"},
    )
    key_id = key["id"]
    key_value = key["value"]
    ctx.on_cleanup(lambda: _safe_delete_api_key(apigw, key_id))

    quota_limit = 5000
    plan = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-plan-"),
        apiStages=[{"apiId": api_id, "stage": stage_name}],
        throttle={"rateLimit": 1.0, "burstLimit": 2},
        quota={"limit": quota_limit, "period": "DAY"},
        tags={"sim2real": "api-key-usage-plan-throttle-enforcement"},
    )
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: _safe_delete_usage_plan(apigw, plan_id))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: _safe_delete_usage_plan_key(apigw, plan_id, key_id))

    url = _invoke_url(ctx, api_id, stage_name, "/limited")

    saw_200 = False
    saw_429 = False
    deadline = time.monotonic() + 45.0
    # Usage-plan/throttle propagation to the data plane has no documented SLA, so we
    # poll a burst of rapid requests repeatedly until we observe both outcomes.
    while time.monotonic() < deadline and not (saw_200 and saw_429):
        for _ in range(10):
            status, _body = _get(url, {"x-api-key": key_value})
            if status == 200:
                saw_200 = True
            elif status == 429:
                saw_429 = True
        if not (saw_200 and saw_429):
            time.sleep(2.0)

    assert saw_200, "expected at least one request within the burst limit to succeed (200)"
    assert saw_429, "expected requests beyond the rate/burst limit to be throttled (429)"

    # GetUsage's count lags live traffic beyond what a bounded check can wait for, so only the report's
    # shape is asserted: one [used, remaining] pair for today with remaining == quota_limit - used.
    today = datetime.datetime.utcnow().date().isoformat()
    usage = apigw.get_usage(usagePlanId=plan_id, keyId=key_id, startDate=today, endDate=today)
    assert usage.get("usagePlanId") == plan_id, f"GetUsage returned wrong usagePlanId: {usage!r}"
    daily_entries = usage.get("items", usage.get("values", {})).get(key_id, [])
    assert len(daily_entries) == 1, (
        f"expected exactly one day of usage for a single-day range, got {daily_entries!r}"
    )
    used, remaining = daily_entries[0]
    assert isinstance(used, int) and isinstance(remaining, int), (
        f"expected a [used, remaining] pair of ints, got {daily_entries[0]!r}"
    )
    assert used >= 0, f"used must be non-negative, got {used}"
    assert remaining == quota_limit - used, (
        f"remaining ({remaining}) must equal the plan's daily quota ({quota_limit}) minus used ({used})"
    )


def _get(url: str, headers: dict[str, str]) -> tuple[int | None, bytes]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError:
        return None, b""


def _invoke_url(ctx, rest_api_id: str, stage: str, path: str) -> str:
    return f"{ctx.rest_api_url(rest_api_id, stage)}{path}"


def _safe_delete_rest_api(apigw, api_id: str) -> None:
    try:
        apigw.delete_rest_api(restApiId=api_id)
    except apigw.exceptions.NotFoundException:
        pass


def _safe_delete_api_key(apigw, key_id: str) -> None:
    try:
        apigw.delete_api_key(apiKey=key_id)
    except apigw.exceptions.NotFoundException:
        pass


def _safe_delete_usage_plan(apigw, plan_id: str) -> None:
    try:
        apigw.delete_usage_plan(usagePlanId=plan_id)
    except apigw.exceptions.NotFoundException:
        pass


def _safe_delete_usage_plan_key(apigw, plan_id: str, key_id: str) -> None:
    try:
        apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    except apigw.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
