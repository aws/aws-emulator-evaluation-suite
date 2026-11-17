"""create-integration-response-duplicate-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-integration-response-duplicate-key-rejected"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """(code, message) of the ClientError fn() raised. An unexpected success RAISES."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateIntegrationResponse on the same integration with an already-used
    IntegrationResponseKey is refused with BadRequestException, and the original is untouched.
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"), ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action", Tags=TAGS,
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    integ_id = agw.create_integration(ApiId=api_id, IntegrationType="MOCK")["IntegrationId"]

    first = agw.create_integration_response(
        ApiId=api_id, IntegrationId=integ_id, IntegrationResponseKey="$default",
        ContentHandlingStrategy="CONVERT_TO_TEXT",
    )
    first_id = first["IntegrationResponseId"]

    code, message = _error(lambda: agw.create_integration_response(
        ApiId=api_id, IntegrationId=integ_id, IntegrationResponseKey="$default",
        ContentHandlingStrategy="CONVERT_TO_BINARY",
    ))
    assert code == "BadRequestException", (
        f"a duplicate IntegrationResponseKey must be refused with BadRequestException, got "
        f"{code}: {message!r}"
    )
    assert message == (
        f"IntegrationResponse with key $default is already present in Integration with ID "
        f"{integ_id}"
    ), f"unexpected message {message!r}"

    unchanged = agw.get_integration_response(
        ApiId=api_id, IntegrationId=integ_id, IntegrationResponseId=first_id
    )
    assert unchanged["ContentHandlingStrategy"] == "CONVERT_TO_TEXT", (
        f"the refused duplicate create must leave the original untouched, got "
        f"{unchanged.get('ContentHandlingStrategy')!r}"
    )
    all_responses = agw.get_integration_responses(ApiId=api_id, IntegrationId=integ_id)["Items"]
    assert len(all_responses) == 1, (
        f"the refused duplicate create must mint no second response, got {all_responses!r}"
    )

    # positive control: a different key on the same integration is accepted.
    second = agw.create_integration_response(
        ApiId=api_id, IntegrationId=integ_id, IntegrationResponseKey="/2\\d\\d/",
        ContentHandlingStrategy="CONVERT_TO_TEXT",
    )
    assert second["IntegrationResponseKey"] == "/2\\d\\d/", (
        f"a non-conflicting key must be accepted, got {second.get('IntegrationResponseKey')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
