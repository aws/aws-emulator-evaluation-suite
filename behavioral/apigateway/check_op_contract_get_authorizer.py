"""op-contract-getAuthorizer."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-getAuthorizer"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAuthorizer returns the exact authorizer config; unknown authorizerId -> NotFoundException."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(name=ctx.unique_name("sim2real-apigw-"), tags={"sim2real": CHECK})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{ctx.region}:123456789012:function:sim2real-fake-authorizer/invocations"
    )
    created = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authz-"),
        type="TOKEN",
        identitySource="method.request.header.Authorization",
        authorizerUri=authorizer_uri,
        authorizerResultTtlInSeconds=120,
    )
    authorizer_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id))

    got = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert got["id"] == authorizer_id, f"expected id {authorizer_id}, got {got.get('id')}"
    assert got["type"] == "TOKEN", f"expected type TOKEN, got {got.get('type')}"
    assert got["identitySource"] == "method.request.header.Authorization", (
        f"expected identitySource method.request.header.Authorization, got {got.get('identitySource')}"
    )
    assert got["authorizerUri"] == authorizer_uri, f"expected authorizerUri {authorizer_uri}, got {got.get('authorizerUri')}"
    assert got["authorizerResultTtlInSeconds"] == 120, (
        f"expected authorizerResultTtlInSeconds 120, got {got.get('authorizerResultTtlInSeconds')}"
    )

    err = _client_error(lambda: apigw.get_authorizer(restApiId=api_id, authorizerId="nonexistent-authz-id"))
    assert err.get("Code") == "NotFoundException", f"expected NotFoundException, got {err.get('Code')!r}"
    assert err.get("Message") == "Invalid Authorizer identifier specified", (
        f"expected the exact NotFound message, got {err.get('Message')!r}"
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
