"""create-deployment-canary-settings-without-stage-name-rejected."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-canary-settings-without-stage-name-rejected"
GROUP = "canary-deployments"
SERVICES = ["apigateway"]


def _retry_throttled(fn, *, attempts=10):
    """fn() retried on TooManyRequestsException, which the control-plane rate limit raises."""
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TooManyRequestsException":
                raise
            if attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


def _delete_rest_api(ag, api_id, *, budget_s=150.0):
    """DeleteRestApi until gone; NotFoundException means gone, any other failure raises."""
    deadline = time.monotonic() + budget_s
    delay = 5.0
    while True:
        try:
            ag.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or time.monotonic() >= deadline:
                raise
        time.sleep(delay)
        delay = min(delay * 2, 30.0)


def _create_api(ctx, ag, body):
    """A REGIONAL REST API whose root GET is a MOCK answering ``body`` as JSON."""
    api_id = _retry_throttled(lambda: ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    ))["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(ag, api_id))
    root = next(i["id"] for i in ag.get_resources(restApiId=api_id)["items"] if i["path"] == "/")
    _retry_throttled(lambda: ag.put_method(restApiId=api_id, resourceId=root, httpMethod="GET",
                                           authorizationType="NONE"))
    _retry_throttled(lambda: ag.put_integration(
        restApiId=api_id, resourceId=root, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'}))
    _retry_throttled(lambda: ag.put_method_response(restApiId=api_id, resourceId=root,
                                                    httpMethod="GET", statusCode="200"))
    _retry_throttled(lambda: ag.put_integration_response(
        restApiId=api_id, resourceId=root, httpMethod="GET", statusCode="200",
        responseTemplates={"application/json": json.dumps(body)}))
    return api_id


def _error(fn):
    """(code, message, HTTP status) of the refusal fn() raises. A call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _deployment_ids(ag, api_id):
    pages = ag.get_paginator("get_deployments").paginate(restApiId=api_id)
    return {d["id"] for page in pages for d in page.get("items", [])}


_CANARY_NEEDS_STAGE = (
    "Invalid deployment content specified.Non null and non empty stageName must be provided for "
    "canary deployment. Provided value is "
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """canarySettings with stageName "" or no stageName is refused, the message naming the value
    given ("" or null), and creates no deployment; the same canary on an existing stage applies."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag, {"ok": True})
    base = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id, stageName="live"))["id"]
    canary = {"percentTraffic": 10.0}

    code, message, status = _error(lambda: ag.create_deployment(
        restApiId=api_id, stageName="", canarySettings=canary))
    assert code == "BadRequestException", f"canary with stageName '' gave {code!r}"
    assert status == 400, f"canary with stageName '' gave HTTP {status!r}, expected 400"
    assert message == _CANARY_NEEDS_STAGE, f"canary with stageName '' gave message {message!r}"

    code, message, status = _error(lambda: ag.create_deployment(
        restApiId=api_id, canarySettings=canary))
    assert code == "BadRequestException", f"canary without stageName gave {code!r}"
    assert status == 400, f"canary without stageName gave HTTP {status!r}, expected 400"
    assert message == _CANARY_NEEDS_STAGE + "null", f"canary without stageName gave message {message!r}"

    ids = _deployment_ids(ag, api_id)
    assert ids == {base}, f"the refused canaries left deployments {sorted(ids)!r}; expected only {base!r}"
    live = ag.get_stage(restApiId=api_id, stageName="live")
    assert "canarySettings" not in live, f"a refused canary still set {live.get('canarySettings')!r}"

    released = _retry_throttled(lambda: ag.create_deployment(
        restApiId=api_id, stageName="live", canarySettings=canary))["id"]
    live = ag.get_stage(restApiId=api_id, stageName="live")
    assert live["deploymentId"] == base, (
        f"a canary release must leave the stage on {base!r}; it points at {live.get('deploymentId')!r}"
    )
    got = live.get("canarySettings") or {}
    assert got.get("deploymentId") == released, (
        f"canarySettings.deploymentId is {got.get('deploymentId')!r}, expected {released!r}"
    )
    assert got.get("percentTraffic") == 10.0, f"canarySettings.percentTraffic is {got.get('percentTraffic')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
