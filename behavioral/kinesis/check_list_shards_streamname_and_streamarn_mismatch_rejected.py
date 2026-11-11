"""list-shards-streamname-and-streamarn-mismatch-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, Tags={"sim2real": "ga-depth-kinesis"}, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")


def _wait_stream_active(c, name, timeout_s=150, interval_s=2):
    _poll(
        lambda: c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )


def _wait_stream_ready(c, name, timeout_s=150):
    _wait_stream_active(c, name, timeout_s=timeout_s)

    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("ResourceInUseException", "ResourceNotFoundException"):
                return None
            raise

    _poll(_shards, lambda shards: bool(shards), 90, 2, f"stream {name} shards addressable")


CHECK = "list-shards-streamname-and-streamarn-mismatch-rejected"
GROUP = 'error-semantics'
SERVICES = ['kinesis']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListShards accepts StreamName with StreamARN only when both name the same stream.

    A name paired with another real stream's ARN is refused with InvalidArgumentException."""
    c = ctx.client("kinesis")
    base = ctx.unique_name("sim2real-behav-kds-")
    name_a = f"{base}-a"
    name_b = f"{base}-b"

    _create_stream_with_retry(c, name_a, ShardCount=1)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name_a, EnforceConsumerDeletion=True))
    _create_stream_with_retry(c, name_b, ShardCount=1)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name_b, EnforceConsumerDeletion=True))

    _wait_stream_ready(c, name_a)
    _wait_stream_ready(c, name_b)
    arn_a = c.describe_stream_summary(StreamName=name_a)["StreamDescriptionSummary"]["StreamARN"]
    arn_b = c.describe_stream_summary(StreamName=name_b)["StreamDescriptionSummary"]["StreamARN"]

    # Positive control: a consistent pair is accepted.
    consistent = c.list_shards(StreamName=name_a, StreamARN=arn_a)
    assert consistent["Shards"], (
        f"ListShards(StreamName={name_a!r}, StreamARN=<{name_a}'s own ARN>) must succeed, "
        f"got {consistent!r}"
    )

    code, message = _error(
        lambda: c.list_shards(StreamName=name_a, StreamARN=arn_b)
    )
    assert code == "InvalidArgumentException", (
        f"ListShards(StreamName={name_a!r}, StreamARN=<{name_b}'s real ARN>) must fail "
        f"InvalidArgumentException — the two parameters name different streams — got "
        f"{code!r}: {message!r}"
    )
    expected_message = (
        f"Input stream name {name_a} doesn't match the inferred name in stream arn {name_b}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: both streams still describe cleanly after the refused mismatched call.
    recheck_a = c.list_shards(StreamName=name_a)
    assert recheck_a["Shards"], f"ListShards(StreamName={name_a!r}) stopped succeeding after the refusal: {recheck_a!r}"
    recheck_b = c.list_shards(StreamName=name_b)
    assert recheck_b["Shards"], f"ListShards(StreamName={name_b!r}) stopped succeeding after the refusal: {recheck_b!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
