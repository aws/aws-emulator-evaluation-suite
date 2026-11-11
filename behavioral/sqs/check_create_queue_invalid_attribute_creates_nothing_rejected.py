"""create-queue-invalid-attribute-creates-nothing-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-queue-invalid-attribute-creates-nothing-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

_TAGS = {"sim2real": "create-queue-invalid-attribute-creates-nothing-rejected"}


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQueue with an out-of-range VisibilityTimeout is refused with InvalidAttributeValue and
    creates no queue; the same name can then be created at once with valid attributes.
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-cqi-")

    created = []

    def _cleanup():
        for u in created:
            sqs.delete_queue(QueueUrl=u)

    ctx.on_cleanup(_cleanup)

    def _create_bad():
        out = sqs.create_queue(
            QueueName=name, Attributes={"VisibilityTimeout": "43201"}, tags=_TAGS)
        created.append(out["QueueUrl"])
        return out

    code, msg = _err(_create_bad)
    assert code == "InvalidAttributeValue", f"VisibilityTimeout=43201 gave code {code!r}"
    assert msg == "Invalid value for the parameter VisibilityTimeout.", (
        f"VisibilityTimeout=43201 gave message {msg!r}"
    )

    code, msg = _err(lambda: sqs.get_queue_url(QueueName=name))
    assert (code, msg) == ("AWS.SimpleQueueService.NonExistentQueue",
                           "The specified queue does not exist."), (
        f"the refused CreateQueue left a resolvable queue behind: GetQueueUrl gave {(code, msg)!r}"
    )

    url = sqs.create_queue(
        QueueName=name, Attributes={"VisibilityTimeout": "43200"}, tags=_TAGS)["QueueUrl"]
    created.append(url)
    assert sqs.get_queue_url(QueueName=name)["QueueUrl"] == url, (
        "positive control: the valid CreateQueue's URL does not resolve by name"
    )
    vt = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]["VisibilityTimeout"]
    assert vt == "43200", f"positive control: the boundary VisibilityTimeout reads back as {vt!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
