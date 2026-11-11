"""http-proxy-payload-format-version-2-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-proxy-payload-format-version-2-rejected"
GROUP = 'routing'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _err(fn):
    """Call fn; return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


PFV2_HTTP_PROXY_MESSAGE = "PayloadFormatVersion 2.0 is not supported for integration of type HTTP_PROXY"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PayloadFormatVersion 2.0 is legal for AWS_PROXY but refused for HTTP_PROXY on Create and
    Update, and a refused call neither adds an integration nor changes the stored 1.0.
    """
    agw = ctx.client("apigatewayv2")
    api = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))
    good_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        IntegrationUri="https://example.com/backend",
        IntegrationMethod="GET",
        PayloadFormatVersion="1.0",
    )["IntegrationId"]
    got = agw.get_integration(ApiId=api_id, IntegrationId=good_id)
    assert got.get("PayloadFormatVersion") == "1.0", (
        f"setup: HTTP_PROXY must round-trip PayloadFormatVersion 1.0, got "
        f"{got.get('PayloadFormatVersion')}"
    )

    code, message = _err(
        lambda: agw.create_integration(
            ApiId=api_id,
            IntegrationType="HTTP_PROXY",
            IntegrationUri="https://example.com/backend2",
            IntegrationMethod="GET",
            PayloadFormatVersion="2.0",
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for HTTP_PROXY + PayloadFormatVersion 2.0, got {code}: "
        f"{message!r}"
    )
    assert message == PFV2_HTTP_PROXY_MESSAGE, (
        f"expected the exact HTTP_PROXY PayloadFormatVersion refusal on create, got {message!r}"
    )
    ids = sorted(i["IntegrationId"] for i in agw.get_integrations(ApiId=api_id).get("Items", []))
    assert ids == [good_id], (
        f"the rejected CreateIntegration must not mint an integration, got {ids}"
    )

    code, message = _err(
        lambda: agw.update_integration(
            ApiId=api_id, IntegrationId=good_id, PayloadFormatVersion="2.0"
        )
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException when patching HTTP_PROXY to PayloadFormatVersion 2.0, "
        f"got {code}: {message!r}"
    )
    assert message == PFV2_HTTP_PROXY_MESSAGE, (
        f"expected the exact HTTP_PROXY PayloadFormatVersion refusal on update, got {message!r}"
    )
    got = agw.get_integration(ApiId=api_id, IntegrationId=good_id)
    assert got.get("PayloadFormatVersion") == "1.0", (
        f"the rejected UpdateIntegration must not partially apply, PayloadFormatVersion is now "
        f"{got.get('PayloadFormatVersion')}"
    )
    assert got.get("IntegrationType") == "HTTP_PROXY", (
        f"IntegrationType must be unchanged, got {got.get('IntegrationType')}"
    )

    account = ctx.client("sts").get_caller_identity()["Account"]
    lambda_uri = f"arn:aws:lambda:{ctx.region}:{account}:function:sim2real-behav-absent-fn"
    proxy_id = agw.create_integration(
        ApiId=api_id,
        IntegrationType="AWS_PROXY",
        IntegrationUri=lambda_uri,
        PayloadFormatVersion="2.0",
    )["IntegrationId"]
    got_proxy = agw.get_integration(ApiId=api_id, IntegrationId=proxy_id)
    assert got_proxy.get("PayloadFormatVersion") == "2.0", (
        f"control: AWS_PROXY must accept PayloadFormatVersion 2.0, got "
        f"{got_proxy.get('PayloadFormatVersion')}"
    )

    agw.update_integration(
        ApiId=api_id, IntegrationId=good_id, IntegrationUri="https://example.com/backend3"
    )
    final = agw.get_integration(ApiId=api_id, IntegrationId=good_id)
    assert final.get("IntegrationUri") == "https://example.com/backend3", (
        f"control: a legal UpdateIntegration must still apply, got {final.get('IntegrationUri')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
