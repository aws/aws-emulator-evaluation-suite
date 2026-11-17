"""describe-field-indexes-nonexistent-log-group-fails."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "describe-field-indexes-nonexistent-log-group-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeFieldIndexes against a log group that was never created is rejected with
    ResourceNotFoundException, distinct from the successful (possibly empty) result for a
    real log group that has no field index policy."""
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-dfineg-lg-")
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    # Positive control: a real, existing log group is accepted (even with no field index set).
    ok = logs.describe_field_indexes(logGroupIdentifiers=[group])
    assert ok["fieldIndexes"] == [], (
        f"expected no field indexes for a group with no index policy, got {ok!r}"
    )

    # Negative: a log group that was never created is rejected.
    missing_group = ctx.unique_name("sim2real-dfineg-missing-")
    code, message = _error(
        lambda: logs.describe_field_indexes(logGroupIdentifiers=[missing_group])
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a log group that was never created, "
        f"got {code!r} {message!r}"
    )
    expected_message = "Log group cannot be found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent: the named log group still does not exist.
    described = logs.describe_log_groups(logGroupNamePrefix=missing_group)["logGroups"]
    assert described == [], f"expected no log groups matching {missing_group!r}, found {described!r}"


def _error(fn: Callable[[], Any]):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
