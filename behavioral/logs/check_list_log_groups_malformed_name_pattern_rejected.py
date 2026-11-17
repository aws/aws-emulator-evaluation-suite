"""list-log-groups-malformed-name-pattern-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "list-log-groups-malformed-name-pattern-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListLogGroups with a logGroupNamePattern that fails the pattern's own regular
    expression is rejected with InvalidParameterException naming the parameter."""
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-llgneg-lg-")
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    # Positive control: a well-formed pattern matching the real log group is accepted,
    # polled against ListLogGroups' own propagation lag from the just-created group.
    valid_pattern = group[:24]
    deadline = time.monotonic() + 60
    names: set[str] = set()
    while time.monotonic() < deadline:
        found = logs.list_log_groups(logGroupNamePattern=valid_pattern)["logGroups"]
        names = {g["logGroupName"] for g in found}
        if group in names:
            break
        time.sleep(2)
    assert group in names, f"expected {group!r} among ListLogGroups results, got {sorted(names)}"

    # Negative: a pattern containing a space is not a legal logGroupNamePattern character.
    bad_pattern = "not a legal pattern"
    code, message = _error(lambda: logs.list_log_groups(logGroupNamePattern=bad_pattern))
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a malformed logGroupNamePattern, got "
        f"{code!r} {message!r}"
    )
    expected_message = (
        "1 validation error detected: Value at 'logGroupNamePattern' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        "(\\^?[\\.\\-_\\/#A-Za-z0-9]{3,512})|(\\^?[\\.\\-_\\/#A-Za-z0-9]{3,24})"
        "(\\|\\^?[\\.\\-_\\/#A-Za-z0-9]{3,24}){0,4}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


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
