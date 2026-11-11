"""canary-deployment-without-stage-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "canary-deployment-without-stage-name-rejected"
GROUP = "deployments-stages"
SERVICES = ["apigateway"]


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected CreateDeployment to reject the stage-less canary, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeployment with canarySettings but no stageName is rejected (a canary can only
    attach to an existing stage), and nothing is deployed; a normal canary attach still works."""
    ag = ctx.client("apigateway")
    api_id = ag.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(_teardown(lambda: ag.delete_rest_api(restApiId=api_id), "NotFoundException"))

    root_id = ag.get_resources(restApiId=api_id)["items"][0]["id"]
    ag.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    ag.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )

    err = _client_error(lambda: ag.create_deployment(restApiId=api_id, canarySettings={"percentTraffic": 50.0}))
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == (
        "Invalid deployment content specified.Non null and non empty stageName must be "
        "provided for canary deployment. Provided value is null"
    ), f"unexpected message {err.get('Message')!r}"

    # Effect absent: the rejected call created no deployment at all.
    deployments = {d["id"] for page in ag.get_paginator("get_deployments").paginate(restApiId=api_id)
                   for d in page["items"]}
    assert deployments == set(), f"expected no deployments after the rejected call, found {deployments!r}"

    # Positive control: the same canarySettings, naming an existing stage, is accepted.
    base = ag.create_deployment(restApiId=api_id)["id"]
    ag.create_stage(
        restApiId=api_id, stageName="prod", deploymentId=base, tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(_teardown(
        lambda: ag.delete_stage(restApiId=api_id, stageName="prod"), "NotFoundException",
    ))

    canary = ag.create_deployment(
        restApiId=api_id, stageName="prod", canarySettings={"percentTraffic": 50.0},
    )["id"]
    stage = ag.get_stage(restApiId=api_id, stageName="prod")
    assert stage["canarySettings"]["deploymentId"] == canary, (
        f"expected the valid canary deployment {canary!r} attached, got {stage.get('canarySettings')!r}"
    )
    assert stage["canarySettings"]["percentTraffic"] == 50.0, (
        f"expected percentTraffic 50.0, got {stage['canarySettings'].get('percentTraffic')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
