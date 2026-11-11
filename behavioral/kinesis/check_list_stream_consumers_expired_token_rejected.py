"""list-stream-consumers-expired-token-rejected."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "list-stream-consumers-expired-token-rejected"
GROUP = "error-semantics"
SERVICES = ["kinesis"]

# Documented behavior: a ListStreamConsumers NextToken is valid for roughly
# 300 seconds; using it after that window returns ExpiredNextTokenException.
# https://docs.aws.amazon.com/kinesis/latest/APIReference/API_ListStreamConsumers.html
_TOKEN_TTL_S = 300

# The message names the token's expiry instant, which AWS chooses; the rest is fixed.
_EXPIRED_TOKEN_RE = re.compile(
    r"NextToken expired at time [A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} UTC \d{4}\. "
    + re.escape("Invoke ListStreamConsumers again to get a new pagination token.")
)


def _client_error(fn):
    """The botocore Error dict ``fn`` raises; an unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(
        f"expected the expired NextToken to be rejected, but the call SUCCEEDED and returned {result!r}"
    )


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/kinesis/latest/APIReference/API_ListStreamConsumers.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A ListStreamConsumers NextToken that has expired is rejected with
    ExpiredNextTokenException rather than returning stale or empty results,
    while a fresh (tokenless) call against the same stream still succeeds."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(StreamName=name, ShardCount=1)
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(ctx, name)
    stream_arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
        "StreamARN"
    ]
    kinesis.add_tags_to_stream(StreamName=name, Tags={"sim2real": "audit"})

    consumer_arns = []
    for i in range(2):
        consumer_name = ctx.unique_name(f"sim2real-consumer-{i}-")
        arn = kinesis.register_stream_consumer(
            StreamARN=stream_arn, ConsumerName=consumer_name, Tags={"sim2real": "audit"}
        )["Consumer"]["ConsumerARN"]
        ctx.on_cleanup(lambda a=arn: kinesis.deregister_stream_consumer(ConsumerARN=a))
        consumer_arns.append(arn)

    first_page = kinesis.list_stream_consumers(StreamARN=stream_arn, MaxResults=1)
    next_token = first_page.get("NextToken")
    assert next_token, "expected a NextToken with 2 consumers and MaxResults=1"

    # Positive control: the SAME token is valid immediately, and pagination
    # with it actually surfaces the second consumer. Without this, "rejects
    # this NextToken after a wait" is indistinguishable from "rejects every
    # NextToken" -- the eventual rejection below would look identical either way.
    second_page = kinesis.list_stream_consumers(StreamARN=stream_arn, NextToken=next_token)
    assert "Consumers" in second_page, f"expected a fresh-token page, got {second_page!r}"
    paginated_arns = {c["ConsumerARN"] for c in first_page["Consumers"]} | {
        c["ConsumerARN"] for c in second_page["Consumers"]
    }
    assert paginated_arns == set(consumer_arns), (
        f"expected fresh pagination to surface both consumers "
        f"(expected {set(consumer_arns)}, got {paginated_arns})"
    )

    # Deadline-bound wait for the NextToken's documented TTL to genuinely elapse -- there is no
    # readiness signal to poll for, only real wall-clock time, so the deadline itself is the bound.
    expiry_deadline = time.monotonic() + _TOKEN_TTL_S + 20
    while time.monotonic() < expiry_deadline:
        time.sleep(5)

    error = _client_error(
        lambda: kinesis.list_stream_consumers(StreamARN=stream_arn, NextToken=next_token)
    )
    code = error.get("Code")
    assert code == "ExpiredNextTokenException", (
        f"expected ExpiredNextTokenException for a NextToken past its {_TOKEN_TTL_S}s TTL, "
        f"got {code!r}"
    )
    message = error.get("Message", "")
    assert _EXPIRED_TOKEN_RE.fullmatch(message), f"unexpected expired-NextToken message {message!r}"

    # Positive control: a fresh call (no stale token) against the same stream
    # still succeeds and still returns both consumers.
    fresh = kinesis.list_stream_consumers(StreamARN=stream_arn)
    fresh_arns = {c["ConsumerARN"] for c in fresh["Consumers"]}
    assert fresh_arns == set(consumer_arns), (
        f"expected a tokenless call to still return both consumers "
        f"(expected {set(consumer_arns)}, got {fresh_arns})"
    )


def _wait_stream_active(ctx, name: str, timeout_s: float = 120.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
            "StreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {name} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
