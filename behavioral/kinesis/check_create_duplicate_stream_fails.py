"""create-duplicate-stream-fails."""
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

def _refusal(fn):
    """Error code and message of a call that MUST be refused. A success is a failure."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

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

def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(c, name, ShardCount=shard_count)
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_ready(c, name)
    return name

CHECK = "create-duplicate-stream-fails"
GROUP = 'error-semantics'
SERVICES = ['kinesis']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStream with a name already in use (even identical params) MUST fail, and the rejected
    call must leave the existing stream exactly as it was."""
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    before = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]

    code, message = _refusal(lambda: c.create_stream(StreamName=name, ShardCount=1))
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}"
    expected = f"Stream {name} under account {ctx.account} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Independent read at the destination: the rejected duplicate must not have touched the
    # stream it collided with.
    after = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
    assert after["StreamARN"] == before["StreamARN"], (
        f"a rejected duplicate CreateStream changed the stream ARN from "
        f"{before['StreamARN']!r} to {after['StreamARN']!r}"
    )
    assert after["OpenShardCount"] == before["OpenShardCount"], (
        f"a rejected duplicate CreateStream changed OpenShardCount from "
        f"{before['OpenShardCount']} to {after['OpenShardCount']}"
    )
    assert after["StreamStatus"] == "ACTIVE", (
        f"a rejected duplicate CreateStream left the stream {name!r} in status "
        f"{after['StreamStatus']!r}, expected it to remain ACTIVE"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
