"""create-queue-name-conflict-different-attributes-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-queue-name-conflict-different-attributes-rejected"
GROUP = "overly-permissive"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQueue on an existing queue name with DIFFERENT attribute values is rejected
    with QueueNameExists and does not mutate the existing queue's attributes; re-issuing
    CreateQueue with the SAME name and IDENTICAL attributes succeeds idempotently."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-sqs-nameconflict-")
    url = sqs.create_queue(
        QueueName=name, Attributes={"VisibilityTimeout": "30"}, tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    code, message = _error(
        lambda: sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "60"})
    )
    # empirically, real AWS returns the wire error code "QueueAlreadyExists" for this
    # condition (the Smithy/API-doc shape name "QueueNameExists" is not the wire code).
    assert code == "QueueAlreadyExists", f"expected QueueAlreadyExists, got {code!r}"
    expected_message = (
        "A queue already exists with the same name and a different value for attribute "
        "VisibilityTimeout"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # the conflicting call must not have mutated the existing queue's attributes
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]
    assert attrs["VisibilityTimeout"] == "30", (
        f"VisibilityTimeout changed to {attrs['VisibilityTimeout']!r} by a rejected CreateQueue call"
    )

    # positive control: identical attributes -> idempotent success, same URL returned
    idempotent = sqs.create_queue(QueueName=name, Attributes={"VisibilityTimeout": "30"})
    assert idempotent["QueueUrl"] == url, (
        f"idempotent CreateQueue returned {idempotent['QueueUrl']!r}, expected {url!r}"
    )

    # independent terminal read, through a different operation than the one that mutated
    looked_up = sqs.get_queue_url(QueueName=name)["QueueUrl"]
    assert looked_up == url, f"GetQueueUrl returned {looked_up!r}, expected {url!r}"


def _error(fn):
    """Call fn(); return the ClientError's (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
