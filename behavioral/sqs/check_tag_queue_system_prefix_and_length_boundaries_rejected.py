"""tag-queue-system-prefix-and-length-boundaries-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-queue-system-prefix-and-length-boundaries-rejected"
GROUP = "limits"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "tag-queue-system-prefix-and-length-boundaries-rejected"}
_KEY_MSG = "Tag keys must be between 1 and 128 characters in length."
_VALUE_MSG = "Tag values must be between 0 and 256 characters in length."
_SYSTEM_MSG = "Caller is an end user and not allowed to mutate system tags"


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A 128-character tag key, 256-character value and empty value are stored; an 'aws:' key,
    empty key, 257-character value, or 129-character UntagQueue key is refused with
    InvalidParameterValue and the exact message, leaving the tag set unchanged."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-tagrules-"), tags=_TAGS)[
        "QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    boundary = {"k" * 128: "v", "long-value": "v" * 256, "empty-value": ""}
    sqs.tag_queue(QueueUrl=url, Tags=boundary)
    want = {**_TAGS, **boundary}
    got = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
    assert got == want, (
        f"boundary tags read back as {sorted((k[:12], len(k), len(v)) for k, v in got.items())!r}"
    )

    for label, tagset, msg in (
        ("aws: key", {"aws:owner": "me", "companion": "x"}, _SYSTEM_MSG),
        ("empty key", {"": "v", "companion": "x"}, _KEY_MSG),
        ("257-char value", {"companion": "x", "big": "v" * 257}, _VALUE_MSG),
    ):
        err = _error(lambda tagset=tagset: sqs.tag_queue(QueueUrl=url, Tags=tagset))
        assert (err.get("Code"), err.get("Message")) == ("InvalidParameterValue", msg), (
            f"TagQueue with a {label} answered {err!r}"
        )
        after = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
        assert after == want, (
            f"the refused TagQueue ({label}) changed the tag set: added "
            f"{sorted(set(after) - set(want))!r}"
        )

    err = _error(lambda: sqs.untag_queue(QueueUrl=url, TagKeys=["long-value", "k" * 129]))
    assert (err.get("Code"), err.get("Message")) == ("InvalidParameterValue", _KEY_MSG), (
        f"UntagQueue with a 129-character key answered {err!r}"
    )
    after = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
    assert after == want, (
        f"the refused UntagQueue removed {sorted(set(want) - set(after))!r}"
    )

    sqs.untag_queue(QueueUrl=url, TagKeys=["k" * 128, "long-value"])
    final = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
    assert final == {**_TAGS, "empty-value": ""}, (
        f"UntagQueue of the 128-character key and one other left {sorted(final)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
