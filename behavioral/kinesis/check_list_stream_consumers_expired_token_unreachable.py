"""list-stream-consumers-expired-token-unreachable."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-stream-consumers-expired-token-unreachable"
GROUP = "error-semantics"
SERVICES = ["kinesis"]

# Documented behavior: a ListStreamConsumers NextToken is valid for roughly 300 seconds;
# using it after that window returns ExpiredNextTokenException rather than stale/empty
# results. https://docs.aws.amazon.com/kinesis/latest/APIReference/API_ListStreamConsumers.html
_TOKEN_TTL_S = 300

# The message names the token's expiry instant, which AWS chooses; the rest is fixed.
_EXPIRED_TOKEN_RE = re.compile(
    r"NextToken expired at time [A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} UTC \d{4}\. "
    + re.escape("Invoke ListStreamConsumers again to get a new pagination token.")
)


def _error_or_raise(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expired NextToken should be rejected, but the call SUCCEEDED and returned {result!r}"
    )


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/kinesis/latest/APIReference/API_ListStreamConsumers.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A ListStreamConsumers NextToken older than its 300s TTL fails with ExpiredNextTokenException,
    while a fresh tokenless call on the same stream still lists both consumers.

    Reference: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_ListStreamConsumers.html
    """
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-lsc-exp-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "ga-depth-kinesis"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    stream_arn = _wait_stream_active(ctx, name)

    consumer_arns = []
    for i in range(2):
        cname = ctx.unique_name(f"sim2real-cons-{i}-")
        arn = kinesis.register_stream_consumer(StreamARN=stream_arn, ConsumerName=cname)[
            "Consumer"
        ]["ConsumerARN"]
        ctx.on_cleanup(lambda a=arn: kinesis.deregister_stream_consumer(ConsumerARN=a))
        consumer_arns.append(arn)

    page1 = kinesis.list_stream_consumers(StreamARN=stream_arn, MaxResults=1)
    token = page1.get("NextToken")
    assert token, "expected a NextToken with 2 consumers and MaxResults=1"

    # Positive control: the fresh token continues pagination to the remaining consumer.
    page2 = kinesis.list_stream_consumers(StreamARN=stream_arn, NextToken=token)
    assert len(page2["Consumers"]) == 1, f"expected 1 remaining consumer, got {page2['Consumers']!r}"

    # Wait past the documented TTL, with margin for clock skew.
    deadline = time.monotonic() + _TOKEN_TTL_S + 30
    while time.monotonic() < deadline:
        time.sleep(5)

    error = _error_or_raise(
        lambda: kinesis.list_stream_consumers(StreamARN=stream_arn, NextToken=token)
    )
    assert error.get("Code") == "ExpiredNextTokenException", (
        f"expected ExpiredNextTokenException for a token past its {_TOKEN_TTL_S}s TTL, "
        f"got {error!r}"
    )
    message = error.get("Message", "")
    assert _EXPIRED_TOKEN_RE.fullmatch(message), f"unexpected expired-NextToken message {message!r}"

    # The rejection is specific to the stale token, not a side effect on the stream.
    fresh = kinesis.list_stream_consumers(StreamARN=stream_arn)
    assert {c["ConsumerARN"] for c in fresh["Consumers"]} == set(consumer_arns), (
        f"expected fresh call to see {consumer_arns!r}, got {fresh['Consumers']!r}"
    )


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 120.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)[
            "StreamDescriptionSummary"
        ]
        if summary["StreamStatus"] == "ACTIVE":
            return summary["StreamARN"]
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

