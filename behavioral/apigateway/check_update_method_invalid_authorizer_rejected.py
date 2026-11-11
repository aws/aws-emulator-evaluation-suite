"""update-method-invalid-authorizer-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-method-invalid-authorizer-rejected"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMethod to authorizationType=CUSTOM without a valid authorizerId is rejected with
    BadRequestException, leaving the method's authorizationType unchanged; switching to a
    self-contained type (AWS_IAM, positive control) succeeds."""
    apigw = ctx.client("apigateway")
    name = ctx.unique_name("sim2real-behav-methodauth-")
    rest_api_id = apigw.create_rest_api(name=name, tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: _safe(lambda: apigw.delete_rest_api(restApiId=rest_api_id)))
    root_id = apigw.get_resources(restApiId=rest_api_id)["items"][0]["id"]

    apigw.put_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET", authorizationType="NONE")

    # Break exactly one precondition: CUSTOM requires a valid authorizerId, which is omitted here.
    err = _client_error(
        lambda: apigw.update_method(
            restApiId=rest_api_id,
            resourceId=root_id,
            httpMethod="GET",
            patchOperations=[{"op": "replace", "path": "/authorizationType", "value": "CUSTOM"}],
        )
    )
    assert err.get("Code") == "BadRequestException", f"expected BadRequestException, got {err.get('Code')!r}"
    assert err.get("Message") == (
        "Invalid authorizer ID specified. Setting the authorization type to CUSTOM or "
        "COGNITO_USER_POOLS requires a valid authorizer."
    ), f"expected the exact missing-authorizer refusal message, got {err.get('Message')!r}"

    # The forbidden effect did not happen: the method's authorizationType is unchanged.
    unaffected = apigw.get_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET")
    assert unaffected["authorizationType"] == "NONE", (
        f"expected authorizationType to remain NONE after the rejected update, "
        f"got {unaffected['authorizationType']!r}"
    )

    # Positive control: a type that needs no authorizerId is accepted by the same operation.
    apigw.update_method(
        restApiId=rest_api_id,
        resourceId=root_id,
        httpMethod="GET",
        patchOperations=[{"op": "replace", "path": "/authorizationType", "value": "AWS_IAM"}],
    )
    updated = apigw.get_method(restApiId=rest_api_id, resourceId=root_id, httpMethod="GET")
    assert updated["authorizationType"] == "AWS_IAM", (
        f"expected authorizationType AWS_IAM after the positive-control update, "
        f"got {updated['authorizationType']!r}"
    )


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
