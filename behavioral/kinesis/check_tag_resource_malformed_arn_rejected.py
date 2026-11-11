"""tag-resource-malformed-arn-rejected."""
from __future__ import annotations

import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-malformed-arn-rejected"
GROUP = "negative-classes"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with a resource ARN that the SDK can route but that breaks the service's
    ARN pattern (a stream ARN with an empty stream name) is rejected with ValidationException,
    leaves the real stream's tags untouched, and a well-formed ARN still tags successfully."""
    kinesis = ctx.client("kinesis")
    raw = _unvalidated_client(ctx, "kinesis")
    name = ctx.unique_name("sim2real-behav-tagarn-")
    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    stream_arn = _wait_stream_active(ctx, name)

    # A string that is not an ARN at all never leaves the SDK: the Kinesis endpoint ruleset
    # parses ResourceARN and fails client-side. An ARN with an empty stream name parses, so the
    # service's own pattern constraint is what refuses it.
    malformed_arn = f"arn:aws:kinesis:{ctx.region}:{ctx.account}:stream/"
    code, message = _client_error(
        lambda: raw.tag_resource(ResourceARN=malformed_arn, Tags={"sim2real": "malformed"})
    )
    assert code == "ValidationException", code
    expected_message = (
        f"1 validation error detected: Value '{malformed_arn}' at 'resourceARN' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        r"arn:aws.*:kinesis:.*:\d{12}:.*(stream|channel|queue)/\S+"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    tags_after_bad_call = kinesis.list_tags_for_resource(ResourceARN=stream_arn).get("Tags", [])
    assert not any(t["Key"] == "sim2real" for t in tags_after_bad_call), (
        "the malformed-ARN call should not have tagged the real stream"
    )

    kinesis.tag_resource(ResourceARN=stream_arn, Tags={"sim2real": "good"})
    tagged = kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]
    assert {"Key": "sim2real", "Value": "good"} in tagged, (
        f"expected sim2real=good in tags after a well-formed ARN call, got {tagged}"
    )


def _client_error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _unvalidated_client(ctx, service):
    """ctx.client with botocore's local parameter validation off, so a value the model forbids
    reaches the service instead of being rejected client-side."""
    return ctx.client(service, config=Config(parameter_validation=False))


def _wait_stream_active(ctx, name, timeout_s=120.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(2)
    raise AssertionError(f"stream {name} never became ACTIVE")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

