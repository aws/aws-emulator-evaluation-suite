"""get-stages-rejects-nonexistent-rest-api."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-stages-rejects-nonexistent-rest-api"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _delete_rest_api(apigw, api_id, *, attempts=10):
    """DeleteRestApi, retried on the control-plane's TooManyRequestsException; NotFoundException
    means it is already gone."""
    for attempt in range(attempts):
        try:
            apigw.delete_rest_api(restApiId=api_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "TooManyRequestsException" or attempt == attempts - 1:
                raise
            time.sleep(min(4.0, 0.2 * (2 ** attempt)) + random.uniform(0, 0.2))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetStages lists the stages created on the REST API; a nonexistent restApiId is
    rejected with NotFoundException rather than an empty list."""
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-"),
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: _delete_rest_api(apigw, api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=root_id, httpMethod="GET", type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    deployment_id = apigw.create_deployment(restApiId=api_id)["id"]
    stage_name = "sim"
    apigw.create_stage(restApiId=api_id, stageName=stage_name, deploymentId=deployment_id)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: apigw.delete_stage(restApiId=api_id, stageName=stage_name)))

    # positive control: GetStages on the real API lists the stage just created
    listed_names = {s["stageName"] for s in apigw.get_stages(restApiId=api_id)["item"]}
    assert stage_name in listed_names, f"expected {stage_name!r} in {sorted(listed_names)!r}"

    # error boundary: a nonexistent restApiId -> NotFoundException, not an empty list
    code, message = _error(lambda: apigw.get_stages(restApiId="nonexistent0"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}: {message!r}"
    assert message == (
        f"Invalid API identifier specified {ctx.account}:nonexistent0"
    ), f"unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
