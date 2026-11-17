"""export-api-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-api-nonexistent-not-found"
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
    """ExportApi on an ApiId that does not exist fails NotFoundException, while a real API's
    export still succeeds afterwards."""
    agw = ctx.client("apigatewayv2")

    real_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-agwv2-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=real_id))
    integration_id = agw.create_integration(
        ApiId=real_id,
        IntegrationType="HTTP_PROXY",
        IntegrationMethod="GET",
        IntegrationUri="https://example.com/sim2real",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]
    agw.create_route(ApiId=real_id, RouteKey="GET /sim2real", Target=f"integrations/{integration_id}")

    bogus_id = "bogus-" + real_id
    code, message = _error(
        lambda: agw.export_api(ApiId=bogus_id, OutputType="JSON", Specification="OAS30")
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException for a nonexistent ApiId, got {code}: {message!r}"
    )
    assert message == f"Invalid API identifier specified {ctx.account}:{bogus_id}", (
        f"expected the exact invalid-API-identifier message for {bogus_id}, got {message!r}"
    )

    # Positive control: the same operation succeeds for a real id, so the rejection above
    # is about THIS id, not about ExportApi being universally denied.
    control = agw.export_api(ApiId=real_id, OutputType="JSON", Specification="OAS30")
    body = control["body"]
    raw = body.read() if hasattr(body, "read") else body
    assert raw, f"expected a non-empty export body for a real API, got {raw!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
