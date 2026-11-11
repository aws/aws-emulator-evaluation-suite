"""op-contract-updateAuthorizer."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-updateAuthorizer"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAuthorizer patches an authorizer's fields in place; nonexistent authorizerId -> NotFoundException."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{ctx.region}:123456789012:function:sim2real-fake-authorizer/invocations"
    )
    original_name = ctx.unique_name("sim2real-authz-orig-")
    created = apigw.create_authorizer(
        restApiId=api_id,
        name=original_name,
        type="TOKEN",
        identitySource="method.request.header.Authorization",
        authorizerUri=authorizer_uri,
        authorizerResultTtlInSeconds=60,
    )
    authorizer_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=authorizer_id))

    new_name = ctx.unique_name("sim2real-authz-renamed-")
    updated = apigw.update_authorizer(
        restApiId=api_id,
        authorizerId=authorizer_id,
        patchOperations=[
            {"op": "replace", "path": "/name", "value": new_name},
            {"op": "replace", "path": "/authorizerResultTtlInSeconds", "value": "300"},
        ],
    )
    assert updated["name"] == new_name, f"expected name {new_name!r}, got {updated['name']!r}"
    assert updated["authorizerResultTtlInSeconds"] == 300, (
        f"expected TTL 300, got {updated['authorizerResultTtlInSeconds']!r}"
    )

    refetched = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert refetched["name"] == new_name, f"expected name {new_name!r}, got {refetched['name']!r}"
    assert refetched["authorizerResultTtlInSeconds"] == 300, (
        f"expected TTL 300, got {refetched['authorizerResultTtlInSeconds']!r}"
    )
    # untouched field is preserved
    assert refetched["authorizerUri"] == authorizer_uri, (
        f"expected authorizerUri {authorizer_uri!r} to survive an unrelated patch, "
        f"got {refetched['authorizerUri']!r}"
    )

    code, message = _error(
        lambda: apigw.update_authorizer(
            restApiId=api_id,
            authorizerId="nonexistent-authz-id",
            patchOperations=[{"op": "replace", "path": "/name", "value": "whatever"}],
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == (
        'Invalid Authorizer identifier specified'
    ), f"unexpected {code} message: {message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it must raise. An
    unexpected success raises, so an over-permissive target cannot pass as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
