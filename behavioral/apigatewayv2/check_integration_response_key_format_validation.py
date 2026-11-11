"""integration-response-key-format-validation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "integration-response-key-format-validation"
GROUP = "responses"
SERVICES = ["apigatewayv2"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A MOCK integration's IntegrationResponseKey is validated in two stages with distinct
    messages: unwrapped keys fail the /pattern/ format, wrapped non-status-code patterns fail a
    second check, and a wrapped status-code pattern is accepted.
    """
    apigw = ctx.client("apigatewayv2")
    api = apigw.create_api(
        Name=ctx.unique_name("sim2real-behav-wsapi-"),
        ProtocolType="WEBSOCKET",
        RouteSelectionExpression="$request.body.action",
        Tags=TAGS,
    )
    api_id = api["ApiId"]
    ctx.on_cleanup(lambda: apigw.delete_api(ApiId=api_id))
    integ_id = apigw.create_integration(ApiId=api_id, IntegrationType="MOCK")["IntegrationId"]

    # Stage 1: an unwrapped, non-"$default" literal fails the wrapper-format check.
    bad_key = "badkey"
    code, message = _error(
        lambda: apigw.create_integration_response(
            ApiId=api_id, IntegrationId=integ_id, IntegrationResponseKey=bad_key
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected_message = (
        "IntegrationResponseKey must be a regular expression pattern of format '/<pattern>/' "
        f"or have a value of $default. Current value is {bad_key}"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Stage 2: wrapped correctly, but the inner pattern is not status-code-shaped -- a
    # DIFFERENT, more specific message, proving this is a second validator and not the first
    # one re-firing on a substring.
    wrapped_non_status = "/error.*/"
    code2, message2 = _error(
        lambda: apigw.create_integration_response(
            ApiId=api_id, IntegrationId=integ_id, IntegrationResponseKey=wrapped_non_status
        )
    )
    assert code2 == "BadRequestException", f"expected BadRequestException, got {code2!r}"
    expected_message2 = (
        "IntegrationResponseKey for non-Lambda Integration must be a valid status code of "
        f"format '[1-5]([0-9]|\\d){{2}}'. Current value is {wrapped_non_status}"
    )
    assert message2 == expected_message2, f"expected {expected_message2!r}, got {message2!r}"
    assert message2 != expected_message, (
        "the wrapped-but-non-status-code rejection must carry a DIFFERENT message than the "
        "unwrapped rejection -- getting the same text back would mean only one validator ran"
    )

    # Effect absent: neither rejected call minted anything.
    items = apigw.get_integration_responses(ApiId=api_id, IntegrationId=integ_id)["Items"]
    assert items == [], f"expected no integration responses after two rejected creates, got {items!r}"

    # Positive control: wrapped AND status-code-shaped is accepted, and reads back intact.
    good_key = "/2\\d\\d/"
    created = apigw.create_integration_response(
        ApiId=api_id, IntegrationId=integ_id, IntegrationResponseKey=good_key
    )
    assert created["IntegrationResponseKey"] == good_key, (
        f"expected the status-code-shaped key to round-trip as {good_key!r}, got {created!r}"
    )
    got = apigw.get_integration_response(
        ApiId=api_id, IntegrationId=integ_id, IntegrationResponseId=created["IntegrationResponseId"]
    )
    assert got["IntegrationResponseKey"] == good_key, (
        f"independent read lost the accepted key: expected {good_key!r}, got {got!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises.
    Throttling is retried.
    """
    for attempt in range(4):
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code")
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < 3:
                time.sleep(3.0 * (attempt + 1))
                continue
            return code, error.get("Message")
        raise AssertionError(
            f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
        )
    raise AssertionError("unreachable: the loop always returns or raises")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
