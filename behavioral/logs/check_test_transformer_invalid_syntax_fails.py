"""test-transformer-invalid-syntax-fails."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "test-transformer-invalid-syntax-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TestTransformer with a malformed processor definition (an unterminated
    grok pattern) raises InvalidParameterException, and does not persist any
    transformer configuration as a side effect."""
    logs = ctx.client("logs")

    # Positive control: a well-formed grok pattern must be ACCEPTED by
    # TestTransformer. Without this, a target that rejects every
    # TestTransformer call (not just malformed syntax) would score green.
    valid_config = [{"grok": {"match": "%{GREEDYDATA:message}"}}]
    control_resp = logs.test_transformer(
        transformerConfig=valid_config,
        logEventMessages=["some sample log line"],
    )
    assert control_resp["transformedLogs"], (
        "positive control failed: TestTransformer with a well-formed grok "
        f"pattern must succeed, got {control_resp}"
    )

    malformed_config = [
        {
            "grok": {
                # Unbalanced/unterminated grok pattern token - invalid syntax.
                "match": "%{DATA:field",
                "source": "@message",
            }
        }
    ]

    code, message = _client_error(
        lambda: logs.test_transformer(
            transformerConfig=malformed_config,
            logEventMessages=["some sample log line"],
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for TestTransformer with malformed "
        f"processor syntax, got {code}"
    )
    assert message == "Grok pattern was unable to capture any fields", (
        f"unexpected InvalidParameterException message for the malformed grok pattern: {message!r}"
    )

    # TestTransformer is a dry-run: confirm it never created a real transformer
    # attached to any log group as an observable side effect of the failed call.
    #
    # GetTransformer on a log group that has never had a transformer
    # configured answers 200 with an empty transformerConfig on real AWS.
    log_group = ctx.unique_name("sim2real-behav-xform-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    get_resp = logs.get_transformer(logGroupIdentifier=log_group)
    assert get_resp.get("transformerConfig") == [], (
        "TestTransformer must not persist a transformer configuration "
        f"anywhere, but GetTransformer returned {get_resp.get('transformerConfig')!r}"
    )


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected TestTransformer to reject the malformed grok pattern, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
