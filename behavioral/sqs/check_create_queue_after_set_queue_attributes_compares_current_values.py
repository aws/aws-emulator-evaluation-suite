"""create-queue-after-set-queue-attributes-compares-current-values."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-queue-after-set-queue-attributes-compares-current-values"
GROUP = "overly-permissive"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "create-queue-after-set-queue-attributes-compares-current-values"}
_PROPAGATION_DEADLINE_S = 90.0


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_attribute(sqs, url: str, attribute: str, want: str) -> str:
    """Poll GetQueueAttributes until ``attribute`` reads ``want``; SetQueueAttributes can take up
    to 60 s to propagate. Raises at the deadline."""
    deadline = time.monotonic() + _PROPAGATION_DEADLINE_S
    while True:
        got = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[attribute])["Attributes"][
            attribute
        ]
        if got == want:
            return got
        if time.monotonic() > deadline:
            raise AssertionError(
                f"SetQueueAttributes did not take effect within {_PROPAGATION_DEADLINE_S}s: "
                f"{attribute} still reads {got!r}, expected {want!r}"
            )
        time.sleep(2.0)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateQueue on an existing name compares against the CURRENT attributes a later
    SetQueueAttributes set, not the creation-time ones: no Attributes, or the current value
    resubmitted, returns the same queue; a differing value is refused naming the current value.
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-cqsqa-")
    url = sqs.create_queue(
        QueueName=name, Attributes={"VisibilityTimeout": "30"}, tags=_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    created_vt = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]
    assert created_vt == "30", f"positive control: VisibilityTimeout read back as {created_vt!r}"

    sqs.set_queue_attributes(QueueUrl=url, Attributes={"VisibilityTimeout": "90"})
    _poll_attribute(sqs, url, "VisibilityTimeout", "90")

    # (1) CreateQueue with NO Attributes at all is accepted as the same queue, and the attribute
    # SetQueueAttributes changed stays at its current value rather than reverting to the
    # creation-time one or to the service's documented default.
    no_attrs = sqs.create_queue(QueueName=name)["QueueUrl"]
    assert no_attrs == url, (
        f"CreateQueue with no Attributes returned {no_attrs!r}, expected the existing queue {url!r}"
    )
    vt_after_no_attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]
    assert vt_after_no_attrs == "90", (
        f"a no-Attributes CreateQueue changed VisibilityTimeout to {vt_after_no_attrs!r}, "
        "expected it to stay at the current value '90'"
    )

    # (2) CreateQueue with a value that differs from the CURRENT one (90), not the creation-time
    # one (30), is refused, and the refusal names the current value.
    code, message = _err(
        lambda: sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "45"})
    )
    assert code == "QueueAlreadyExists", f"expected QueueAlreadyExists, got {code!r}"
    expected_message = (
        "A queue already exists with the same name and a different value for attribute "
        "VisibilityTimeout"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    vt_after_conflict = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["VisibilityTimeout"]
    )["Attributes"]["VisibilityTimeout"]
    assert vt_after_conflict == "90", (
        f"the refused CreateQueue changed VisibilityTimeout to {vt_after_conflict!r}"
    )

    # (3) CreateQueue with the CURRENT value (90) re-submitted, which differs from the
    # creation-time value (30), is accepted as the same queue.
    matched = sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "90"})["QueueUrl"]
    assert matched == url, (
        f"CreateQueue with the current VisibilityTimeout returned {matched!r}, expected {url!r}"
    )
    vt_final = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]
    assert vt_final == "90", f"VisibilityTimeout read {vt_final!r} after the matching re-create"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
