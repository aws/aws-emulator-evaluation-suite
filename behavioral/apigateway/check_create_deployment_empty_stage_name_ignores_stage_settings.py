"""create-deployment-empty-stage-name-ignores-stage-settings."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-deployment-empty-stage-name-ignores-stage-settings"
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


def _deployment_ids(ag, api_id):
    pages = ag.get_paginator("get_deployments").paginate(restApiId=api_id)
    return {d["id"] for page in pages for d in page.get("items", [])}


def _stage_names(ag, api_id):
    return sorted(s["stageName"] for s in ag.get_stages(restApiId=api_id).get("item", []))


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With stageName "", CreateDeployment creates a readable deployment and no stage, and applies
    stageDescription, variables and tracingEnabled nowhere; with a stage name they land on that stage."""
    ag = ctx.client("apigateway")
    api_id = _create_api(ctx, ag, {"ok": True})
    settings = {"stageDescription": "from-deployment", "variables": {"color": "blue"},
                "tracingEnabled": True}

    created = _retry_throttled(lambda: ag.create_deployment(
        restApiId=api_id, stageName="", description="stageless", **settings))
    stageless = created.get("id")
    assert isinstance(stageless, str) and stageless, f"CreateDeployment returned no id: {created!r}"
    read = ag.get_deployment(restApiId=api_id, deploymentId=stageless)
    assert read["id"] == stageless, f"GetDeployment returned id {read.get('id')!r}, expected {stageless!r}"
    assert read.get("description") == "stageless", (
        f"GetDeployment description is {read.get('description')!r}, expected 'stageless'"
    )
    assert _deployment_ids(ag, api_id) == {stageless}, (
        f"GetDeployments lists {sorted(_deployment_ids(ag, api_id))!r}, expected only {stageless!r}"
    )
    stages = _stage_names(ag, api_id)
    assert stages == [], f"stage settings with an empty stageName created stages {stages!r}"

    _retry_throttled(lambda: ag.create_stage(
        restApiId=api_id, stageName="bare", deploymentId=stageless))
    bare = ag.get_stage(restApiId=api_id, stageName="bare")
    assert bare["deploymentId"] == stageless, (
        f"stage 'bare' points at {bare.get('deploymentId')!r}, expected {stageless!r}"
    )
    assert "variables" not in bare, (
        f"variables sent with the stageless deployment leaked onto a later stage: {bare.get('variables')!r}"
    )
    assert "description" not in bare, (
        f"stageDescription leaked onto a later stage: {bare.get('description')!r}"
    )
    assert bare["tracingEnabled"] is False, (
        f"tracingEnabled leaked onto a later stage: {bare.get('tracingEnabled')!r}"
    )

    named = _retry_throttled(lambda: ag.create_deployment(
        restApiId=api_id, stageName="named", **settings))["id"]
    stage = ag.get_stage(restApiId=api_id, stageName="named")
    assert stage["deploymentId"] == named, (
        f"stage 'named' points at {stage.get('deploymentId')!r}, expected {named!r}"
    )
    assert stage.get("variables") == {"color": "blue"}, (
        f"stage 'named' variables are {stage.get('variables')!r}, expected {{'color': 'blue'}}"
    )
    assert stage.get("description") == "from-deployment", (
        f"stage 'named' description is {stage.get('description')!r}, expected 'from-deployment'"
    )
    assert stage["tracingEnabled"] is True, (
        f"stage 'named' tracingEnabled is {stage.get('tracingEnabled')!r}, expected True"
    )
    stages = _stage_names(ag, api_id)
    assert stages == ["bare", "named"], f"GetStages lists {stages!r}, expected ['bare', 'named']"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
