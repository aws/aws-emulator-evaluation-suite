"""list-tags-for-resource-nonexistent-arn-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-tags-for-resource-nonexistent-arn-fails"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource against a syntactically valid but non-existent stream ARN fails with
    ResourceNotFoundException rather than returning an empty tag list, while the same call
    against a real stream succeeds and returns its tags."""
    kinesis = ctx.client("kinesis")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bogus_name = ctx.unique_name("sim2real-behav-missing-")
    bogus_arn = f"arn:aws:kinesis:{ctx.region}:{account_id}:stream/{bogus_name}"

    error = _client_error(lambda: kinesis.list_tags_for_resource(ResourceARN=bogus_arn))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error.get('Code')}"
    )
    expected_message = f"Stream {bogus_name} under account {account_id} not found."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    _stream_name, stream_arn = _create_stream(ctx)
    kinesis.tag_resource(ResourceARN=stream_arn, Tags={"sim2real-behav-tag": "present"})
    tags = {t["Key"]: t["Value"] for t in kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]}
    actual = tags.get("sim2real-behav-tag")
    assert actual == "present", f"expected sim2real-behav-tag=present on real stream, got {actual!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_stream_active(kinesis, stream_name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {stream_name} never became ACTIVE within {timeout_s}s")


def _create_stream(ctx):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-kls-")
    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, name)
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
