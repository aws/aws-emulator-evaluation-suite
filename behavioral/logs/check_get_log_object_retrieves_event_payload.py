"""get-log-object-retrieves-event-payload."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-log-object-retrieves-event-payload"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLogObject rejects a pointer it never minted with InvalidParameterException.

    A genuine pointer needs an OTLP event over 1 MB split into a Large Log Object, so only the
    format boundary is exercisable in-check; DescribeLogGroups is the positive control.
    """

    logs = ctx.client("logs")

    bogus_pointer = f"sim2real-unreachable-llo-{ctx.unique_name('ptr-')}"
    code, message = _error(lambda: logs.get_log_object(logObjectPointer=bogus_pointer))
    assert code == "InvalidParameterException", (
        f"expected GetLogObject to reject an unrecognized logObjectPointer with "
        f"InvalidParameterException, got {code!r}"
    )
    expected_message = "Invalid log object pointer format."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the rejection above is targeted, not a target that rejects everything.
    describe_resp = logs.describe_log_groups(limit=1)
    assert "logGroups" in describe_resp, (
        f"positive control failed: describe_log_groups did not return logGroups: {describe_resp!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError code and message, raising if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
