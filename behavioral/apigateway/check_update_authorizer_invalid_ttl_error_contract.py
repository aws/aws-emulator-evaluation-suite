"""update-authorizer-invalid-ttl-error-contract."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "update-authorizer-invalid-ttl-error-contract"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAuthorizer rejects TTL 3601 (over the 3600s bound) with BadRequestException, unchanged.
    The boundary value 3600 is accepted, so the rejection is specific to exceeding the bound.
    """
    apigw = ctx.client("apigateway")
    sts = ctx.client("sts")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-apigw-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    account_id = sts.get_caller_identity()["Account"]
    fn_name = ctx.unique_name("sim2real-authfn-")
    authorizer_uri = (
        f"arn:aws:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{ctx.region}:{account_id}:function:{fn_name}/invocations"
    )

    initial_ttl = 300
    authorizer_id = apigw.create_authorizer(
        restApiId=api_id,
        name=ctx.unique_name("sim2real-authz-"),
        type="TOKEN",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=initial_ttl,
    )["id"]

    code, message = _client_error(
        lambda: apigw.update_authorizer(
            restApiId=api_id, authorizerId=authorizer_id,
            patchOperations=[{"op": "replace", "path": "/authorizerResultTtlInSeconds", "value": "3601"}],
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException for TTL over the max, got {code}"
    assert message == "Authorizer result TTL outside allowable range. TTL must be between 0 and 3600 seconds.", (
        f"expected the exact TTL-range refusal message naming the 3600s bound, got: {message!r}"
    )

    # Effect absent: TTL must still be the original value.
    unchanged = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert unchanged["authorizerResultTtlInSeconds"] == initial_ttl, (
        f"TTL changed to {unchanged['authorizerResultTtlInSeconds']} despite the rejected patch"
    )

    # Positive control: the boundary value itself (3600) is accepted.
    apigw.update_authorizer(
        restApiId=api_id, authorizerId=authorizer_id,
        patchOperations=[{"op": "replace", "path": "/authorizerResultTtlInSeconds", "value": "3600"}],
    )
    at_bound = apigw.get_authorizer(restApiId=api_id, authorizerId=authorizer_id)
    assert at_bound["authorizerResultTtlInSeconds"] == 3600, (
        f"expected the boundary TTL 3600 to be accepted and stored, "
        f"got {at_bound['authorizerResultTtlInSeconds']}"
    )


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return its botocore (code, message); raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (err.response["Error"]["Code"], err.response["Error"].get("Message", ""))
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
