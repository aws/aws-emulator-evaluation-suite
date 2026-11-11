"""reserved-header-mapping-refused-at-create."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reserved-header-mapping-refused-at-create"

GROUP = "routing"

SERVICES = ["apigatewayv2"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CreateIntegration refuses a request-parameter mapping that targets the reserved
    ``Authorization`` header, and a twin mapping an ordinary header is accepted unchanged.

    Reference: https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-parameter-mapping.html
    """
    agw = ctx.client("apigatewayv2")
    api_id = agw.create_api(
        Name=ctx.unique_name("sim2real-behav-httpapi-reserved-"),
        ProtocolType="HTTP",
        Tags=_resource_tags(),
    )["ApiId"]
    ctx.on_cleanup(lambda: ctx.client("apigatewayv2").delete_api(ApiId=api_id))

    code, message = _error(
        lambda: agw.create_integration(
            ApiId=api_id,
            IntegrationType="HTTP_PROXY",
            PayloadFormatVersion="1.0",
            IntegrationUri="https://example.com",
            IntegrationMethod="GET",
            RequestParameters={"overwrite:header.authorization": "'sim2real-value'"},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}: {message!r}"
    assert message == (
        "Invalid mapping expression specified: Validation Result: warnings : [], errors : "
        "[Operations on header authorization are restricted]"
    ), f"unexpected message {message!r}"

    # The reserved-header refusal must be scoped to that one header: an ordinary header mapping
    # on the same API is accepted, proving the API itself can take a valid mapping.
    accepted = agw.create_integration(
        ApiId=api_id,
        IntegrationType="HTTP_PROXY",
        PayloadFormatVersion="1.0",
        IntegrationUri="https://example.com",
        IntegrationMethod="GET",
        RequestParameters={"overwrite:header.x-sim2real-ordinary": "'sim2real-value'"},
    )
    integration_id = accepted["IntegrationId"]
    stored = agw.get_integration(ApiId=api_id, IntegrationId=integration_id)
    assert stored.get("RequestParameters", {}).get(
        "overwrite:header.x-sim2real-ordinary"
    ) == "'sim2real-value'", (
        f"the ordinary-header mapping must be stored as authored, got "
        f"{stored.get('RequestParameters')!r}"
    )


def _resource_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
