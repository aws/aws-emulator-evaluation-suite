"""untag-resource-malformed-arn-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-malformed-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _wait_active(c, name, timeout_s=150.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(interval_s)
    raise AssertionError(f"stream {name!r} never reached ACTIVE within {timeout_s}s")


def _tag_keys(c, arn):
    return {t["Key"] for t in c.list_tags_for_resource(ResourceARN=arn)["Tags"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with a syntactically-typed ResourceARN that breaks the operation's own ARN
    pattern (a stream ARN with an empty stream name) is rejected with ValidationException,
    leaves the real stream's tags untouched, and the well-formed ARN still untags it."""
    c = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-untagarn-")
    c.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: c.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    stream_arn = _wait_active(c, name)
    c.tag_resource(ResourceARN=stream_arn, Tags={"sim2real-marker": "present"})

    malformed_arn = f"arn:aws:kinesis:{ctx.region}:{ctx.account}:stream/"
    code, message = _error(
        lambda: c.untag_resource(ResourceARN=malformed_arn, TagKeys=["sim2real-marker"])
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = (
        f"1 validation error detected: Value '{malformed_arn}' at 'resourceARN' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: "
        r"arn:aws.*:kinesis:.*:\d{12}:.*(stream|channel|queue)/\S+"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_bad_call = _tag_keys(c, stream_arn)
    assert "sim2real-marker" in after_bad_call, (
        f"the malformed-ARN call must not have removed the real stream's tag, "
        f"tags are now {after_bad_call!r}"
    )

    c.untag_resource(ResourceARN=stream_arn, TagKeys=["sim2real-marker"])
    after_good_call = _tag_keys(c, stream_arn)
    assert "sim2real-marker" not in after_good_call, (
        f"UntagResource with the well-formed ARN should have removed the tag, "
        f"tags are now {after_good_call!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
