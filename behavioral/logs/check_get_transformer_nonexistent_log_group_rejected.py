"""get-transformer-nonexistent-log-group-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-transformer-nonexistent-log-group-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]

_LOG_GROUP_NOT_FOUND = ("ResourceNotFoundException", "The specified log group does not exist.")


def _expect_error(fn, code, message) -> None:
    """Call fn(); assert it raises exactly (code, message). Raises if fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == code, f"expected code {code!r}, got {err!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected {code!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetTransformer on a log group that was never created raises ResourceNotFoundException
    with its exact message, while the same call against a real log group with a configured
    transformer succeeds."""
    logs = ctx.client("logs")

    real_group = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=real_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=real_group))

    logs.put_transformer(
        logGroupIdentifier=real_group, transformerConfig=[{"parseJSON": {}}]
    )

    # Positive control: a real log group with a configured transformer is readable.
    real = logs.get_transformer(logGroupIdentifier=real_group)
    assert real["transformerConfig"] == [{"parseJSON": {}}], (
        f"expected the configured transformer back, got {real['transformerConfig']!r}"
    )

    # Negative: a log group name that was never created, not merely one lacking a
    # transformer, is rejected with the same not-found code and message.
    missing_group = ctx.unique_name("sim2real-behav-lg-absent-")
    _expect_error(lambda: logs.get_transformer(logGroupIdentifier=missing_group), *_LOG_GROUP_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
