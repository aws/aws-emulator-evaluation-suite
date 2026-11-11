"""tag-queue-over-fifty-tags-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-queue-over-fifty-tags-rejected"
GROUP = 'tagging'
SERVICES = ['sqs']

_LIMIT = 50


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _tags(sqs, url):
    return sqs.list_queue_tags(QueueUrl=url).get("Tags", {})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A queue's tag set is capped at 50 across calls: 51 at once or a 51st is refused with nothing
    applied, untagging an absent key is a no-op, and removing one key makes room for another."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-t50-")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    msg_over = f"Too many tags added for queue {name}."

    code, msg = _err(lambda: sqs.tag_queue(
        QueueUrl=url, Tags={f"k{i}": "v" for i in range(_LIMIT + 1)}))
    assert (code, msg) == ("InvalidParameterValue", msg_over), (
        f"51 tags in one call gave {(code, msg)!r}"
    )
    assert _tags(sqs, url) == {}, f"the refused 51-tag call stored {len(_tags(sqs, url))} tags"

    full = {f"k{i}": "v" for i in range(_LIMIT)}
    full["sim2real"] = CHECK
    del full["k0"]
    sqs.tag_queue(QueueUrl=url, Tags=full)
    assert _tags(sqs, url) == full, (
        f"exactly 50 tags were accepted but {len(_tags(sqs, url))} read back"
    )

    code, msg = _err(lambda: sqs.tag_queue(QueueUrl=url, Tags={"extra": "v"}))
    assert (code, msg) == ("InvalidParameterValue", msg_over), (
        f"a 51st tag on a full queue gave {(code, msg)!r}"
    )
    after = _tags(sqs, url)
    assert after == full, (
        f"the refused 51st tag changed the tag set: {len(after)} tags, "
        f"'extra' {'present' if 'extra' in after else 'absent'}"
    )

    sqs.untag_queue(QueueUrl=url, TagKeys=["sim2real-not-a-key"])
    assert _tags(sqs, url) == full, "untagging an absent key changed the tag set"

    sqs.untag_queue(QueueUrl=url, TagKeys=["k1"])
    sqs.tag_queue(QueueUrl=url, Tags={"extra": "v"})
    expected = {k: v for k, v in full.items() if k != "k1"}
    expected["extra"] = "v"
    final = _tags(sqs, url)
    assert final == expected, (
        f"after freeing one slot the new tag did not fit: {len(final)} tags, 'extra' "
        f"{'present' if 'extra' in final else 'absent'}, 'k1' "
        f"{'present' if 'k1' in final else 'absent'}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
