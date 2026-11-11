"""op-contract-getAuthorizers."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-getAuthorizers"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAuthorizers lists exactly the authorizers created on the API; nonexistent restApiId -> NotFoundException."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"),
        tags={"sim2real": "op-contract-getAuthorizers"},
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{ctx.region}:123456789012:function:sim2real-fake-authorizer/invocations"
    )
    names = {ctx.unique_name("sim2real-authz-a-"), ctx.unique_name("sim2real-authz-b-")}
    created_ids = set()
    for name in names:
        created = apigw.create_authorizer(
            restApiId=api_id,
            name=name,
            type="TOKEN",
            identitySource="method.request.header.Authorization",
            authorizerUri=authorizer_uri,
        )
        authorizer_id = created["id"]
        created_ids.add(authorizer_id)
        ctx.on_cleanup(lambda aid=authorizer_id: apigw.delete_authorizer(restApiId=api_id, authorizerId=aid))

    listing = apigw.get_authorizers(restApiId=api_id)
    items = listing["items"]
    assert len(items) == 2, f"expected exactly 2 authorizers, got {len(items)}"
    listed_ids = {item["id"] for item in items}
    listed_names = {item["name"] for item in items}
    assert listed_ids == created_ids, f"expected ids {created_ids}, got {listed_ids}"
    assert listed_names == names, f"expected names {names}, got {listed_names}"

    code, message = _error(lambda: apigw.get_authorizers(restApiId="nonexistent-api-id"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == (
        f"Invalid API identifier specified {ctx.account}:nonexistent-api-id"
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
