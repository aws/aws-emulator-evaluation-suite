"""websocket-connect-custom-authorizer-nonexistent-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "websocket-connect-custom-authorizer-nonexistent-id-rejected"
GROUP = "authorizers"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) fn() raised. RAISES if fn() succeeded -- success is not a code."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<no code>"), err.get("Message", "")
    raise AssertionError(f"expected the call to fail, it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRoute on a WEBSOCKET $connect route with AuthorizationType=CUSTOM and a never-created
    AuthorizerId fails with BadRequestException and leaves no route; with NONE it is created."""
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    integ = agw.create_integration(ApiId=api_id, IntegrationType="MOCK")["IntegrationId"]

    bogus_authorizer = "nonexistent123"
    code, message = _error(
        lambda: agw.create_route(
            ApiId=api_id,
            RouteKey="$connect",
            Target=f"integrations/{integ}",
            AuthorizationType="CUSTOM",
            AuthorizerId=bogus_authorizer,
        )
    )
    assert code == "BadRequestException", (
        f"a CUSTOM authorizer id that was never created must be rejected with "
        f"BadRequestException, got {code!r}: {message!r}"
    )
    expected_message = (
        "Invalid authorizer ID specified. Setting the authorization type to CUSTOM or "
        "COGNITO_USER_POOLS requires a valid authorizer."
    )
    assert message == expected_message, (
        f"the refusal of authorizer {bogus_authorizer!r} must carry the exact message "
        f"{expected_message!r}, got {message!r}"
    )
    before_control = agw.get_routes(ApiId=api_id)["Items"]
    assert before_control == [], (
        f"the rejected CreateRoute must leave no route behind, but GetRoutes shows {before_control!r}"
    )

    # Positive control: the same api and integration with NONE creates a route, so the
    # rejection above is specific to the bogus authorizer.
    control = agw.create_route(
        ApiId=api_id, RouteKey="$connect", Target=f"integrations/{integ}", AuthorizationType="NONE"
    )
    assert control.get("AuthorizationType") == "NONE", (
        f"the positive control route must report AuthorizationType=NONE, got {control!r}"
    )
    after_control = agw.get_routes(ApiId=api_id)["Items"]
    assert any(r["RouteId"] == control["RouteId"] for r in after_control), (
        f"the positive control route {control['RouteId']} must appear in GetRoutes, got {after_control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
