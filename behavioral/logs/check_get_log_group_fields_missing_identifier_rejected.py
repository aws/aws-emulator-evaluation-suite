"""get-log-group-fields-missing-identifier-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-log-group-fields-missing-identifier-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]

_MISSING_IDENTIFIER = ("ValidationException", "Either LogGroupName or LogGroupArn must be provided.")


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
    """GetLogGroupFields with neither logGroupName nor logGroupIdentifier raises
    ValidationException with its exact message, while supplying logGroupIdentifier alone
    on a real log group succeeds."""
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    # Positive control: logGroupIdentifier alone identifies a real log group.
    ok = logs.get_log_group_fields(logGroupIdentifier=group)
    assert ok["logGroupFields"] == [], f"expected no fields on a fresh log group, got {ok!r}"

    # Negative: neither identifier form is supplied.
    _expect_error(lambda: logs.get_log_group_fields(), *_MISSING_IDENTIFIER)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
