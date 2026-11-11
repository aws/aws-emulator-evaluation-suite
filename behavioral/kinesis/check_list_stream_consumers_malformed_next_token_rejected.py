"""list-stream-consumers-malformed-next-token-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-stream-consumers-malformed-next-token-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStreamConsumers rejects a mangled NextToken with InvalidArgumentException.

    The valid token and an unpaginated listing of the 2 consumers keep working afterwards.

    Reference:
    https://docs.aws.amazon.com/kinesis/latest/APIReference/API_ListStreamConsumers.html"""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-lsctok-")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, Tags={"sim2real": "ga-depth-kinesis"}
    )
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    )
    _wait_stream_active(ctx, stream_name)
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)[
        "StreamDescriptionSummary"
    ]["StreamARN"]

    for i in range(2):
        name = ctx.unique_name(f"sim2real-lsctok-c{i}-")
        arn = kinesis.register_stream_consumer(StreamARN=stream_arn, ConsumerName=name)[
            "Consumer"
        ]["ConsumerARN"]
        ctx.on_cleanup(lambda a=arn: kinesis.deregister_stream_consumer(ConsumerARN=a))

    first_page = kinesis.list_stream_consumers(StreamARN=stream_arn, MaxResults=1)
    token = first_page.get("NextToken")
    assert token, "expected a NextToken when paginating with MaxResults=1 and 2 consumers"

    # Positive control: the freshly-issued token is valid immediately.
    fresh_page = kinesis.list_stream_consumers(StreamARN=stream_arn, NextToken=token)
    assert "Consumers" in fresh_page, f"expected a Consumers key in {fresh_page!r}"

    # A mangled token exercises token validation without waiting out the 300s TTL; it is
    # InvalidArgumentException, while ExpiredNextTokenException is for a well-formed expired token.
    bogus_token = token[:-8] + "deadbeef" if len(token) > 8 else token + "deadbeef"
    assert bogus_token != token, f"mangled token {bogus_token!r} must differ from {token!r}"
    error = _client_error(
        lambda: kinesis.list_stream_consumers(StreamARN=stream_arn, NextToken=bogus_token)
    )
    code = error.get("Code")
    assert code == "InvalidArgumentException", (
        f"expected InvalidArgumentException for a malformed NextToken, got {code!r}"
    )
    expected_message = "Invalid NextToken."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Positive control: only the bad token is rejected, not the stream.
    control = kinesis.list_stream_consumers(StreamARN=stream_arn)
    assert len(control["Consumers"]) == 2, (
        f"expected 2 consumers on an unpaginated read, got {len(control['Consumers'])}"
    )

    # And the original, validly-issued token (still within its TTL) still works --
    # rejection is specific to the malformed token, not a side effect of probing it.
    still_valid = kinesis.list_stream_consumers(StreamARN=stream_arn, NextToken=token)
    assert "Consumers" in still_valid, f"expected the original token to still work, got {still_valid!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _wait_stream_active(ctx, stream_name, timeout_s=120.0, interval_s=3.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)[
            "StreamDescriptionSummary"
        ]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stream {stream_name} never became ACTIVE (last status={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
