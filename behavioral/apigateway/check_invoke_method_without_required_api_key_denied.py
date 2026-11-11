"""invoke-method-without-required-api-key-denied."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "invoke-method-without-required-api-key-denied"
GROUP = "overly-permissive"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A deployed method with apiKeyRequired=true rejects an invocation lacking a valid,
    usage-plan-linked API key with 403 Forbidden and never reaches the integration, while
    the identical request WITH a valid key succeeds (positive control, same file)."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": "invoke-method-without-required-api-key-denied"},
    )
    api_id = api["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        authorizationType="NONE",
        apiKeyRequired=True,
    )
    apigw.put_integration(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=root_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"ok": true}'},
    )

    stage_name = "test"
    apigw.create_deployment(restApiId=api_id, stageName=stage_name)

    usage_plan = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-behav-up-"),
        apiStages=[{"apiId": api_id, "stage": stage_name}],
        tags={"sim2real": "invoke-method-without-required-api-key-denied"},
    )
    plan_id = usage_plan["id"]
    ctx.on_cleanup(lambda: apigw.delete_usage_plan(usagePlanId=plan_id))

    key = apigw.create_api_key(
        name=ctx.unique_name("sim2real-behav-key-"),
        enabled=True,
        tags={"sim2real": "invoke-method-without-required-api-key-denied"},
    )
    key_id = key["id"]
    key_value = key["value"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key_id))

    invoke_url = f"{ctx.rest_api_url(api_id, stage_name)}/"

    # Without an API key: rejected, integration never invoked (403 Forbidden).
    status, body = _poll_until(
        lambda: _invoke(invoke_url, {}),
        lambda r: r[0] is not None,
        timeout_s=90.0,
    )
    assert status == 403, f"expected 403 without api key, got {status}: {body!r}"
    assert json.loads(body).get("message") == "Forbidden"

    # Positive control: the same request WITH the valid, usage-plan-linked key succeeds.
    status2, body2 = _poll_until(
        lambda: _invoke(invoke_url, {"x-api-key": key_value}),
        lambda r: r[0] == 200,
        timeout_s=90.0,
    )
    assert status2 == 200, f"expected 200 with a valid api key, got {status2}: {body2!r}"
    assert json.loads(body2) == {"ok": True}


def _invoke(url: str, headers: dict) -> tuple:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError:
        return None, ""


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
