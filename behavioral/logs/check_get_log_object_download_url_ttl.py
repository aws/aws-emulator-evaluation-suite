"""get-log-object-download-url-ttl."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-log-object-download-url-ttl"
GROUP = 'log-events'
SERVICES = ['logs']


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLogObject rejects client-built pointers with InvalidParameterException.

    Both a malformed string and a group:timestamp:id-shaped pointer that was never issued get
    'Invalid log object pointer format.', after a DescribeLogGroups control succeeds.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-logobject-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))

    # Positive control: the same client/credentials genuinely reach the logs API
    # and succeed on an ordinary call. Without this, the two rejections below
    # cannot distinguish "GetLogObject enforces pointer validity" from a target
    # that unconditionally rejects every GetLogObject call (e.g. one that never
    # implements pointer resolution at all).
    describe_resp = svc.describe_log_groups(limit=1)
    assert "logGroups" in describe_resp, (
        f"positive control failed: describe_log_groups did not return logGroups, got {describe_resp!r}"
    )

    # A structurally invalid pointer (empty-ish / clearly malformed) must be
    # rejected as a parameter error, not passed through to a lookup.
    code_malformed, message_malformed = _error(
        lambda: svc.get_log_object(logObjectPointer="not-a-real-pointer")
    )
    assert code_malformed == "InvalidParameterException", (
        f"expected a specific validation error for a malformed pointer, got {code_malformed!r}"
    )
    expected_message = "Invalid log object pointer format."
    assert message_malformed == expected_message, (
        f"expected message {expected_message!r}, got {message_malformed!r}"
    )

    # A syntactically pointer-shaped but never-issued value must not resolve to
    # any real/synthetic object.
    bogus_pointer = f"{group}:0000000000000:00000000000000000000000000000000"
    code_bogus, message_bogus = _error(lambda: svc.get_log_object(logObjectPointer=bogus_pointer))
    assert code_bogus == "InvalidParameterException", (
        f"expected a never-issued pointer to be rejected with a specific validation error, got {code_bogus!r}"
    )
    expected_message = "Invalid log object pointer format."
    assert message_bogus == expected_message, (
        f"expected message {expected_message!r}, got {message_bogus!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
