"""export-api-invalid-output-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "export-api-invalid-output-type-rejected"
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
    """ExportApi with an OutputType outside JSON|YAML is refused with BadRequestException; the
    same call with OutputType=JSON succeeds and returns the exported document.
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-exportapi-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    integration_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationMethod="GET",
        IntegrationUri="https://example.com/probe",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]
    agw.create_route(ApiId=api_id, RouteKey="GET /probe", Target=f"integrations/{integration_id}")

    code, message = _error(lambda: agw.export_api(
        ApiId=api_id, Specification="OAS30", OutputType="XML"
    ))
    assert code == "BadRequestException", (
        f"ExportApi with OutputType='XML': expected BadRequestException, got {code}: {message!r}"
    )
    assert message == (
        "Output type is XML. Output type should be one of following : JSON, YAML."
    ), f"unexpected message {message!r}"

    good = agw.export_api(ApiId=api_id, Specification="OAS30", OutputType="JSON")
    body = good["body"].read()
    assert body, f"ExportApi with a valid OutputType returned an empty body: {body!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
