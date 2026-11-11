"""delete-nonexistent-stream-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")

def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")

def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
        if last == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} not ACTIVE within {timeout_s}s. Last status: {last!r}")

def _wait_stream_deleted(c, name, timeout_s=150, interval_s=2):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
        except ClientError as exc:
            last = exc.response.get("Error", {}).get("Code")
            if last == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} still describable {timeout_s}s after delete. Last observation: {last!r}")

CHECK = "delete-nonexistent-stream-fails"
GROUP = 'error-semantics'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStream on an unknown stream name MUST fail; DeleteStream on a real stream MUST succeed."""
    c = ctx.client("kinesis")
    real_name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, real_name, ShardCount=1)
    ctx.on_cleanup(lambda: _swallow(
        lambda: c.delete_stream(StreamName=real_name, EnforceConsumerDeletion=True)
    ))
    _wait_stream_active(c, real_name)

    live = c.describe_stream_summary(StreamName=real_name)["StreamDescriptionSummary"]
    assert live["StreamName"] == real_name, f"expected {real_name}, got {live['StreamName']!r}"

    # Positive control: DeleteStream on a stream that genuinely exists succeeds and the
    # stream becomes independently unreachable, so the negative below cannot pass merely
    # because DeleteStream always fails.
    c.delete_stream(StreamName=real_name, EnforceConsumerDeletion=True)
    _wait_stream_deleted(c, real_name)

    missing_name = real_name + "-absent"
    code, message = _error(lambda: c.delete_stream(StreamName=missing_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Stream {missing_name} under account {ctx.account} not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
