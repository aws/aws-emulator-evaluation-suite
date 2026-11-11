"""stage-repoint-unblocks-old-deployment-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stage-repoint-unblocks-old-deployment-delete"
GROUP = 'state-machine'
SERVICES = ['apigateway']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Repointing a stage's /deploymentId to a newer deployment releases the old
    one, which then becomes deletable -- the deploy/stage reference state machine."""
    ag = ctx.client("apigateway")
    api_id = _create_rest_api(ctx, ag)
    root_id = _root_resource_id(ag, api_id)
    resource_id = ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="v")["id"]
    _make_mock_method(ag, api_id, resource_id)

    first = ag.create_deployment(restApiId=api_id, stageName="live")["id"]
    second = ag.create_deployment(restApiId=api_id)["id"]
    assert second != first, f"expected a distinct deployment id, got {second!r} twice"

    stage = ag.get_stage(restApiId=api_id, stageName="live")
    assert stage["deploymentId"] == first, f"expected stage to point at {first}, got {stage['deploymentId']}"

    ag.update_stage(
        restApiId=api_id,
        stageName="live",
        patchOperations=[{"op": "replace", "path": "/deploymentId", "value": second}],
    )
    repointed = ag.get_stage(restApiId=api_id, stageName="live")
    assert repointed["deploymentId"] == second, f"stage did not repoint: {repointed['deploymentId']}"

    # Now that no stage references it, the old deployment can be deleted.
    ag.delete_deployment(restApiId=api_id, deploymentId=first)
    code, message = _error(lambda: ag.get_deployment(restApiId=api_id, deploymentId=first))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Deployment identifier specified", f"unexpected message: {message!r}"

    # the dead deployment id is unusable, not just unlisted: a mutation naming it also fails.
    revert_code, revert_message = _error(lambda: ag.update_stage(
        restApiId=api_id,
        stageName="live",
        patchOperations=[{"op": "replace", "path": "/deploymentId", "value": first}],
    ))
    assert revert_code == "BadRequestException", (
        f"expected BadRequestException repointing to the deleted deployment, got {revert_code}"
    )
    assert revert_message == "Deployment id does not exist", (
        f"unexpected message: {revert_message!r}"
    )

    remaining = {d["id"] for d in ag.get_deployments(restApiId=api_id)["items"]}
    assert second in remaining and first not in remaining, f"unexpected deployments {remaining}"


# ===== helpers =====


def _error(fn):
    """Call fn(), which real AWS refuses; return the ClientError's (Code, Message).
    An unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("real AWS refuses this call, but it SUCCEEDED")


def _delete_with_backoff(fn, *, deadline_s: float = 240.0) -> None:
    """Delete, retrying API Gateway's delete throttle (1 DeleteRestApi per 30 s per account) and
    in-flight conflicts every 2 s; an already-deleted resource is fine, any other error raises."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            retryable = ("TooManyRequestsException", "ConflictException", "LimitExceededException")
            if code not in retryable or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_rest_api(ctx, ag, name=None, **kwargs):
    """Create a REGIONAL REST API (registered for teardown) and return its id."""
    name = name or ctx.unique_name("sim2real-behav-apigw-")
    kwargs.setdefault("endpointConfiguration", {"types": ["REGIONAL"]})
    resp = ag.create_rest_api(name=name, **kwargs)
    api_id = resp["id"]
    ctx.on_cleanup(lambda: _delete_with_backoff(lambda: ag.delete_rest_api(restApiId=api_id)))
    return api_id


def _root_resource_id(ag, rest_api_id: str) -> str:
    """The id of the root ('/') resource of a REST API."""
    for item in ag.get_resources(restApiId=rest_api_id)["items"]:
        if item["path"] == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


def _make_mock_method(
    ag,
    rest_api_id: str,
    resource_id: str,
    http_method: str = "GET",
    status_code: str = "200",
    response_template: str = '{"message": "ok"}',
) -> None:
    """Wire up a full MOCK-integration method (method -> integration -> method
    response -> integration response) so it can be deployed and invoked."""
    ag.put_method(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        authorizationType="NONE",
    )
    ag.put_integration(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    ag.put_method_response(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        statusCode=status_code,
    )
    ag.put_integration_response(
        restApiId=rest_api_id,
        resourceId=resource_id,
        httpMethod=http_method,
        statusCode=status_code,
        responseTemplates={"application/json": response_template},
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
