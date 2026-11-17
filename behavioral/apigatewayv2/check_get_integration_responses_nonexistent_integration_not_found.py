"""get-integration-responses-nonexistent-integration-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-integration-responses-nonexistent-integration-not-found"
GROUP = "error-semantics"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """Call fn; return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIntegrationResponses against an IntegrationId that does not exist fails
    NotFoundException, while the same call lists a real integration's own response."""
    agw = ctx.client("apigatewayv2")

    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-ws-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=TAGS,
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))

    integration_id = agw.create_integration(ApiId=api_id, IntegrationType="MOCK")["IntegrationId"]

    bogus_integration_id = "bogus-" + integration_id
    code, message = _error(
        lambda: agw.get_integration_responses(ApiId=api_id, IntegrationId=bogus_integration_id)
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException for a nonexistent IntegrationId, got {code}: {message!r}"
    )
    assert message == "Invalid Integration identifier specified", (
        f"expected the exact invalid-integration-identifier message, got {message!r}"
    )

    # Positive control: the same operation lists a real integration's own response, so the
    # rejection above is about THIS integration id, not a universal denial.
    response_id = agw.create_integration_response(
        ApiId=api_id,
        IntegrationId=integration_id,
        IntegrationResponseKey="$default",
    )["IntegrationResponseId"]

    items = agw.get_integration_responses(ApiId=api_id, IntegrationId=integration_id)["Items"]
    assert any(item["IntegrationResponseId"] == response_id for item in items), (
        f"expected response {response_id!r} in GetIntegrationResponses for {integration_id!r}, "
        f"got {[i['IntegrationResponseId'] for i in items]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
