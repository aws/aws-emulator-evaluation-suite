"""deregister-stream-consumer-twice-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-stream-consumer-twice-not-found"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


def _poll(probe, pred, timeout_s=150.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last saw {last!r}")


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _wait_active(c, name):
    def _status():
        return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]

    _poll(_status, lambda s: s == "ACTIVE", description=f"stream {name!r} ACTIVE")
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]


def _wait_consumer_status(c, stream_arn, consumer_name, status):
    def _probe():
        try:
            desc = c.describe_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
            return desc["ConsumerDescription"]["ConsumerStatus"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    return _poll(_probe, lambda v: v == status, description=f"consumer {consumer_name!r} reaching {status!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterStreamConsumer on a consumer already removed fails with ResourceNotFoundException
    and its exact message, after the first deregistration (which removes it) succeeds."""
    c = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-kds-")
    c.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    stream_arn = _wait_active(c, name)

    consumer_name = ctx.unique_name("sim2real-behav-consumer-")
    c.register_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
    _wait_consumer_status(c, stream_arn, consumer_name, "ACTIVE")

    # positive control / the first delete: removing a live consumer succeeds.
    c.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
    _wait_consumer_status(c, stream_arn, consumer_name, "ResourceNotFoundException")

    code, message = _error(
        lambda: c.deregister_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = f"Consumer {consumer_name} under stream: {name}, account {ctx.account} not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    describe_code, _ = _error(
        lambda: c.describe_stream_consumer(StreamARN=stream_arn, ConsumerName=consumer_name)
    )
    assert describe_code == "ResourceNotFoundException", (
        f"a read of the dead consumer must also fail not-found, got {describe_code!r}"
    )

    consumers = c.list_stream_consumers(StreamARN=stream_arn)["Consumers"]
    assert consumer_name not in {x["ConsumerName"] for x in consumers}, (
        f"the deregistered consumer must not reappear in ListStreamConsumers: {consumers!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
