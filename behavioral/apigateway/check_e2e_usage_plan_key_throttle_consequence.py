"""e2e-usage-plan-key-throttle-consequence."""
from __future__ import annotations

import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-usage-plan-key-throttle-consequence"
GROUP = "e2e"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A usage plan's throttle settings actually gate real invocations of a deployed,
    api-key-protected method; deleting the plan cascades its key association away."""
    apigw = ctx.client("apigateway")

    api = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-e2e-throttle-"),
        tags={"sim2real": "usage-plan-key-throttle-consequence"},
    )
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
        responseTemplates={"application/json": '{"message": "ok"}'},
    )

    deployment = apigw.create_deployment(restApiId=api_id)
    stage_name = "prod"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment["id"])

    key = apigw.create_api_key(
        name=ctx.unique_name("sim2real-e2e-key-"),
        enabled=True,
        tags={"sim2real": "usage-plan-key-throttle-consequence"},
    )
    key_id = key["id"]
    key_value = key["value"]
    ctx.on_cleanup(lambda: _delete_api_key_ignore_missing(apigw, key_id))

    plan = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-e2e-plan-"),
        apiStages=[{"apiId": api_id, "stage": stage_name}],
        throttle={"burstLimit": 1, "rateLimit": 1},
        tags={"sim2real": "usage-plan-key-throttle-consequence"},
    )
    plan_id = plan["id"]
    ctx.on_cleanup(lambda: _delete_usage_plan_ignore_missing(apigw, plan_id))

    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key_id, keyType="API_KEY")

    url = f"{ctx.rest_api_url(api_id, stage_name)}/hello"

    # Throttle settings on a usage plan can take a short while to become effective; poll by
    # hammering the endpoint with the valid key until we see both a successful call (positive
    # control -- the key/stage association genuinely works) and a throttled one (429).
    seen_200 = False
    seen_429 = False
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline and not (seen_200 and seen_429):
        for _ in range(5):
            status = _get_status(url, {"x-api-key": key_value})
            if status == 200:
                seen_200 = True
            elif status == 429:
                seen_429 = True
            if seen_200 and seen_429:
                break
        if not (seen_200 and seen_429):
            time.sleep(1.0)

    assert seen_200, "valid api key call never succeeded (positive control failed)"
    assert seen_429, "burst throttle (burstLimit=1, rateLimit=1) never produced a 429"

    # Delete the plan; its key association is a child of the plan and must disappear with it.
    # A usage plan cannot be deleted while it still has API stages associated with it, so the
    # stage association must be removed first (real AWS returns BadRequestException otherwise).
    apigw.update_usage_plan(
        usagePlanId=plan_id,
        patchOperations=[
            {"op": "remove", "path": "/apiStages", "value": f"{api_id}:{stage_name}"}
        ],
    )
    apigw.delete_usage_plan(usagePlanId=plan_id)
    not_found = ("NotFoundException", "Invalid Usage Plan ID specified")
    err = _error(lambda: apigw.get_usage_plan(usagePlanId=plan_id))
    assert err == not_found, f"expected the deleted plan to 404 with {not_found!r}, got {err!r}"

    # A mutation on the dead plan id must also fail, not just a read.
    mutate_err = _error(
        lambda: apigw.update_usage_plan(
            usagePlanId=plan_id,
            patchOperations=[{"op": "replace", "path": "/description", "value": "x"}],
        )
    )
    assert mutate_err == not_found, (
        f"expected a mutation on the deleted plan to 404 with {not_found!r}, got {mutate_err!r}"
    )

    # The specific claim in this check's docstring: the key<->plan association is gone,
    # not merely that the plan itself is gone.
    assoc_err = _error(
        lambda: apigw.get_usage_plan_key(usagePlanId=plan_id, keyId=key_id)
    )
    assert assoc_err == not_found, (
        f"expected the plan<->key association to be gone with the plan ({not_found!r}), got {assoc_err!r}"
    )

    # The api key itself is untouched by deleting the plan (only the association is gone).
    still_there = apigw.get_api_key(apiKey=key_id)
    assert still_there["id"] == key_id, (
        f"expected api key {key_id} to survive usage plan deletion, got {still_there!r}"
    )

    apigw.delete_api_key(apiKey=key_id)


def _get_status(url: str, headers: dict) -> int:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except urllib.error.URLError:
        return -1


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


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
