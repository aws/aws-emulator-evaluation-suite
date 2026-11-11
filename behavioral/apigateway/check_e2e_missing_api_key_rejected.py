"""e2e-missing-api-key-rejected."""
from __future__ import annotations

import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-missing-api-key-rejected"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A deployed method with apiKeyRequired=True rejects real invocations that omit the
    x-api-key header, the MOCK integration is never reached, and the same call succeeds once
    a valid, enabled key from an associated usage plan is supplied (positive control)."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(name=ctx.unique_name("sim2real-e2e-nokey-"))
    api_id = api["id"]
    ctx.on_cleanup(lambda: _delete_rest_api_ignore_missing(apigw, api_id))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    resource = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="hello")
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
        responseTemplates={"application/json": '{"message": "reached-integration"}'},
    )

    deployment = apigw.create_deployment(restApiId=api_id)
    stage_name = "prod"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment["id"])

    key = apigw.create_api_key(name=ctx.unique_name("sim2real-e2e-nokey-key-"), enabled=True)
    key_id = key["id"]
    key_value = key["value"]
    ctx.on_cleanup(lambda: _delete_api_key_ignore_missing(apigw, key_id))

    plan = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-e2e-nokey-plan-"),
        apiStages=[{"apiId": api_id, "stage": stage_name}],
    )
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: _delete_usage_plan_ignore_missing(apigw, plan_id))
    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")

    url = f"{ctx.rest_api_url(api_id, stage_name)}/hello"

    # Break exactly one thing: no x-api-key header at all.
    status_missing, body_missing = _get(url, {})
    assert status_missing == 403, (
        f"expected 403 for a request with no x-api-key on a method with "
        f"apiKeyRequired=True, got {status_missing}: {body_missing!r}"
    )
    assert _message(body_missing) == "Forbidden", (
        f'expected the opaque body {{"message":"Forbidden"}} for a missing api key, '
        f"got {body_missing!r}"
    )
    assert "reached-integration" not in body_missing, (
        f"the MOCK integration must never run for a request with no api key, "
        f"got {body_missing!r}"
    )

    # Positive control: same call, same key, this time WITH the required header succeeds.
    # Key-to-usage-plan association can take a few seconds to propagate on real AWS, so poll
    # a bounded window rather than asserting on the very first attempt.
    status_ok, body_ok = _poll_for_200(url, {"x-api-key": key_value}, timeout_s=60.0)
    assert status_ok == 200, (
        f"expected 200 once the valid, usage-plan-linked api key is supplied, "
        f"got {status_ok}: {body_ok!r}"
    )
    assert "reached-integration" in body_ok, (
        f"expected the MOCK integration to run once the api key is accepted, "
        f"got {body_ok!r}"
    )


def _message(body: str):
    import json

    try:
        return json.loads(body).get("message")
    except (ValueError, AttributeError):
        return None


def _get(url: str, headers: dict):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")


def _poll_for_200(url: str, headers: dict, timeout_s: float = 60.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = (None, "")
    while time.monotonic() < deadline:
        last = _get(url, headers)
        if last[0] == 200:
            return last
        time.sleep(2.0)
    raise AssertionError(
        f"GET {url} with a valid, usage-plan-linked api key never returned 200 "
        f"within {timeout_s}s; last={last!r}"
    )


def _delete_rest_api_ignore_missing(apigw, api_id: str) -> None:
    try:
        apigw.delete_rest_api(restApiId=api_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_api_key_ignore_missing(apigw, key_id: str) -> None:
    try:
        apigw.delete_api_key(apiKey=key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_usage_plan_ignore_missing(apigw, plan_id: str) -> None:
    try:
        apigw.delete_usage_plan(usagePlanId=plan_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
