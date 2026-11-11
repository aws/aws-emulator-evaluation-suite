"""list-tags-for-resource-nonexistent-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-tags-for-resource-nonexistent-arn-rejected"
GROUP = "negative-classes"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a well-formed but nonexistent stream ARN fails with
    ResourceNotFoundException -- a distinct failure shape from the malformed-ARN
    boundary -- while the same call against a real stream ARN still succeeds."""
    kinesis = ctx.client("kinesis")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    missing_name = ctx.unique_name("sim2real-behav-missing-")
    missing_arn = f"arn:aws:kinesis:{ctx.region}:{account}:stream/{missing_name}"

    error = _client_error(lambda: kinesis.list_tags_for_resource(ResourceARN=missing_arn))
    assert error.get("Code") == "ResourceNotFoundException", error
    expected_message = f"Stream {missing_name} under account {account} not found."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    real_name = ctx.unique_name("sim2real-behav-real-")
    kinesis.create_stream(StreamName=real_name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=real_name, EnforceConsumerDeletion=True))
    stream_arn = _wait_stream_active(ctx, real_name)
    kinesis.tag_resource(ResourceARN=stream_arn, Tags={"sim2real": "present"})
    tags = kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]
    assert {"Key": "sim2real", "Value": "present"} in tags, f"expected sim2real=present in {tags}"


def _client_error(fn):
    """The botocore Error dict ``fn`` raises; an unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
