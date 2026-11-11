"""http-api-integration-timeout-above-30000-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "http-api-integration-timeout-above-30000-rejected"
GROUP = 'integration'
SERVICES = ['apigatewayv2']

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _error(fn):
    """(code, message) of the ClientError fn() raised; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _integration_ids(agw, api_id):
    ids, token = set(), None
    while True:
        kw = {"ApiId": api_id, "NextToken": token} if token else {"ApiId": api_id}
        page = agw.get_integrations(**kw)
        ids.update(i["IntegrationId"] for i in page.get("Items", []))
        token = page.get("NextToken")
        if not token:
            return ids


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """HTTP API integration TimeoutInMillis is capped at 30000 ms: 30001 is refused on Create and
    Update with AWS's exact message, and a refused call creates nothing and leaves the stored value.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-quotas.html
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-"), ProtocolType="HTTP", Tags=TAGS
    )["ApiId"]
    ctx.on_cleanup(lambda: agw.delete_api(ApiId=api_id))

    def _create(timeout_ms):
        return agw.create_integration(
            ApiId=api_id,
            IntegrationType="HTTP_PROXY",
            IntegrationUri="https://example.com/slow",
            IntegrationMethod="GET",
            PayloadFormatVersion="1.0",
            TimeoutInMillis=timeout_ms,
        )

    good = _create(30000)
    good_id = good["IntegrationId"]
    assert good.get("TimeoutInMillis") == 30000, (
        f"CreateIntegration must accept the 30000 ms ceiling, echoed {good.get('TimeoutInMillis')!r}"
    )
    assert agw.get_integration(ApiId=api_id, IntegrationId=good_id).get("TimeoutInMillis") == 30000

    expected = "Timeout should be between 50 ms and 30000 ms"
    code, message = _error(lambda: _create(30001))
    assert code == "BadRequestException", (
        f"CreateIntegration TimeoutInMillis=30001: expected BadRequestException, got {code}: {message!r}"
    )
    assert message == expected, (
        f"CreateIntegration TimeoutInMillis=30001: expected message {expected!r}, got {message!r}"
    )
    assert _integration_ids(agw, api_id) == {good_id}, (
        "a refused CreateIntegration still added an integration to the API"
    )

    code, message = _error(
        lambda: agw.update_integration(ApiId=api_id, IntegrationId=good_id, TimeoutInMillis=30001)
    )
    assert code == "BadRequestException", (
        f"UpdateIntegration TimeoutInMillis=30001: expected BadRequestException, got {code}: {message!r}"
    )
    assert message == expected, (
        f"UpdateIntegration TimeoutInMillis=30001: expected message {expected!r}, got {message!r}"
    )
    stored = agw.get_integration(ApiId=api_id, IntegrationId=good_id).get("TimeoutInMillis")
    assert stored == 30000, f"the refused UpdateIntegration changed the stored timeout to {stored!r}"

    agw.update_integration(ApiId=api_id, IntegrationId=good_id, TimeoutInMillis=5000)
    stored = agw.get_integration(ApiId=api_id, IntegrationId=good_id).get("TimeoutInMillis")
    assert stored == 5000, f"a legal UpdateIntegration to 5000 ms read back as {stored!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
