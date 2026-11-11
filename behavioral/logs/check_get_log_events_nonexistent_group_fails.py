"""get-log-events-nonexistent-group-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")

CHECK = "get-log-events-nonexistent-group-fails"
GROUP = 'log-events'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLogEvents on a nonexistent log group fails with ResourceNotFoundException and its message.

    A positive control on a real group/stream proves the read path works otherwise.
    """
    svc = ctx.client("logs")

    group = ctx.unique_name("sim2real-behav-lg-get-events-")
    stream = ctx.unique_name("sim2real-behav-ls-get-events-")
    svc.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=group))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": "sim2real-behav-probe"}],
    )
    control = svc.get_log_events(logGroupName=group, logStreamName=stream)
    assert "events" in control, f"expected GetLogEvents on a real group/stream to succeed, got {control!r}"

    missing_group = ctx.unique_name("sim2real-behav-lg-missing-get-")
    code, message = _error(
        lambda: svc.get_log_events(logGroupName=missing_group, logStreamName="anything")
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = "The specified log group does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
