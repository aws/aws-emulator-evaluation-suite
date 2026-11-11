"""create-deployment-whitespace-stage-name-rejected."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-whitespace-stage-name-rejected"
GROUP = "deployments-stages"
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


def _stage_names(ag, api_id):
    return sorted(s["stageName"] for s in ag.get_stages(restApiId=api_id).get("item", []))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A blank stageName (" ") is refused with "Stage name must be non-empty" and creates neither
    a deployment nor a stage, while "" is accepted as no stage and a named stage is created."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag, {"ok": True})

    control = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id, stageName=""))["id"]
    assert _deployment_ids(ag, api_id) == {control}, (
        f"GetDeployments lists {sorted(_deployment_ids(ag, api_id))!r}, expected only {control!r}"
    )

    code, message, status = _error(lambda: ag.create_deployment(restApiId=api_id, stageName=" "))
    assert code == "BadRequestException", f"a blank stageName gave {code!r}, expected BadRequestException"
    assert status == 400, f"a blank stageName gave HTTP {status!r}, expected 400"
    assert message == "Stage name must be non-empty", f"unexpected message {message!r}"

    ids = _deployment_ids(ag, api_id)
    assert ids == {control}, f"the refused call left deployments {sorted(ids)!r}; expected only {control!r}"
    stages = _stage_names(ag, api_id)
    assert stages == [], f"the refused call left stages {stages!r}"

    named = _retry_throttled(lambda: ag.create_deployment(restApiId=api_id, stageName="live"))["id"]
    stage = ag.get_stage(restApiId=api_id, stageName="live")
    assert stage["deploymentId"] == named, (
        f"stage 'live' points at {stage.get('deploymentId')!r}, expected {named!r}"
    )
    assert _deployment_ids(ag, api_id) == {control, named}, (
        f"GetDeployments lists {sorted(_deployment_ids(ag, api_id))!r}, expected {sorted({control, named})!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
