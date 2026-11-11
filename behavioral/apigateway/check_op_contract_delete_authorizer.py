"""op-contract-delete-authorizer."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-delete-authorizer"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAuthorizer removes an unreferenced authorizer; deleting one still referenced
    by a Method's authorizerId is rejected with ConflictException, and succeeds once that
    Method reference is removed."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-api-"),
        tags={"sim2real": "op-contract-delete-authorizer"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]

    dummy_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{ctx.region}:123456789012:function:sim2real-nonexistent/invocations"
    )
    authorizer_name = ctx.unique_name("sim2real-apigw-authz-")
    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=authorizer_name,
        type="TOKEN",
        authorizerUri=dummy_uri,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=0,
    )["id"]

    method = apigw.put_method(
        restApiId=api_id,
        resourceId=root_id,
        httpMethod="GET",
        authorizationType="CUSTOM",
        authorizerId=authorizer_id,
    )
    assert method["authorizerId"] == authorizer_id

    # error boundary: authorizer still referenced by a Method -> ConflictException, not deleted
    err = _client_error(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id))
    assert err.get("Code") == "ConflictException", f"expected ConflictException, got {err.get('Code')!r}"
    assert err.get("Message") == f"Cannot delete authorizer '{authorizer_name}', is referenced in method: GET//", (
        f"expected the exact in-use message, got {err.get('Message')!r}"
    )
    still_there = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert still_there["id"] == authorizer_id

    # positive control: once the Method reference is removed, delete succeeds
    apigw.delete_method(restApiId=api_id, resourceId=root_id, httpMethod="GET")
    apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    err2 = _client_error(lambda: apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id))
    assert err2.get("Code") == "NotFoundException", f"expected NotFoundException reading a deleted authorizer, got {err2.get('Code')!r}"
    assert err2.get("Message") == "Invalid Authorizer identifier specified", (
        f"expected the exact NotFound message from GetAuthorizer, got {err2.get('Message')!r}"
    )

    # a mutation on the dead id must fail too, not just a read
    err3 = _client_error(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id))
    assert err3.get("Code") == "NotFoundException", f"double-delete on a gone authorizer: expected NotFoundException, got {err3.get('Code')!r}"
    assert err3.get("Message") == "Invalid Authorizer identifier specified", (
        f"expected the exact NotFound message from DeleteAuthorizer, got {err3.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
