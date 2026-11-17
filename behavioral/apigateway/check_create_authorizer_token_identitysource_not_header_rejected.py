"""create-authorizer-token-identitysource-not-header-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-authorizer-token-identitysource-not-header-rejected"
GROUP = "negative-classes"
SERVICES = ["apigateway"]

_BAD_IDENTITY_SOURCE = "method.request.querystring.token"
_REJECTED = (
    "BadRequestException",
    f"Invalid token source expression: {_BAD_IDENTITY_SOURCE}. "
    "The source must be a method request header, matching "
    "'method.request.header.[a-zA-Z0-9._-]+'",
)


def _teardown(undo, *not_found: str):
    """Cleanup running undo(); only the resource's own not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAuthorizer of type TOKEN refuses an identitySource that is not a single
    method.request.header.* expression and creates nothing; the same value pointed at a
    header on the same API succeeds."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-authz-src-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(_teardown(lambda: apigw.delete_rest_api(restApiId=api_id), "NotFoundException"))

    region = ctx.region
    authorizer_uri = (
        f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/"
        f"arn:aws:lambda:{region}:123456789012:function:fake/invocations"
    )

    bad_name = ctx.unique_name("sim2real-behav-authz-bad-")
    expect_error(
        lambda: apigw.create_authorizer(
            restApiId=api_id,
            name=bad_name,
            type="TOKEN",
            authorizerUri=authorizer_uri,
            identitySource=_BAD_IDENTITY_SOURCE,
        ),
        *_REJECTED,
    )

    after_rejection = apigw.get_authorizers(restApiId=api_id)["items"]
    assert after_rejection == [], (
        f"expected no authorizer on a fresh API after the rejection, got {after_rejection!r}"
    )

    good_name = ctx.unique_name("sim2real-behav-authz-ok-")
    created = apigw.create_authorizer(
        restApiId=api_id,
        name=good_name,
        type="TOKEN",
        authorizerUri=authorizer_uri,
        identitySource="method.request.header.token",
    )
    ctx.on_cleanup(
        _teardown(
            lambda: apigw.delete_authorizer(restApiId=api_id, authorizerId=created["id"]),
            "NotFoundException",
        )
    )
    assert created["type"] == "TOKEN", f"expected type TOKEN, got {created.get('type')!r}"
    assert created["identitySource"] == "method.request.header.token", (
        f"expected identitySource 'method.request.header.token', got {created.get('identitySource')!r}"
    )

    after_control = apigw.get_authorizers(restApiId=api_id)["items"]
    names = {a["name"] for a in after_control}
    assert names == {good_name}, (
        f"expected only the control authorizer {good_name!r} on the API, got {names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
