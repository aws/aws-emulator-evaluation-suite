"""permission-operations-on-a-deleted-queue-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "permission-operations-on-a-deleted-queue-rejected"
GROUP = "lifecycle"
SERVICES = ["sqs", "sts"]

_NOT_FOUND = "AWS.SimpleQueueService.NonExistentQueue"
_NOT_FOUND_MSG = "The specified queue does not exist."
_SETTLE_S = 60.0


def _error(fn) -> dict:
    """The botocore Error dict ``fn`` raises. An unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_quietly(sqs, url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != _NOT_FOUND:
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddPermission and RemovePermission on a queue deleted earlier in the check are each
    refused with NonExistentQueue once an independent read already reports it gone, while a
    sibling queue still grants and then revokes the same permission."""
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    base = ctx.unique_name("sim2real-behav-permdel-")

    doomed = sqs.create_queue(QueueName=base + "-gone", tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, doomed))
    sibling = sqs.create_queue(QueueName=base + "-kept", tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_quietly(sqs, sibling))

    # Positive control: AddPermission and RemovePermission both work on a live queue.
    control_label = ctx.unique_name("sim2realCtrlLabel")
    sqs.add_permission(
        QueueUrl=sibling, Label=control_label, AWSAccountIds=[account], Actions=["SendMessage"]
    )
    policy_after_add = sqs.get_queue_attributes(QueueUrl=sibling, AttributeNames=["Policy"])[
        "Attributes"
    ]["Policy"]
    assert control_label in policy_after_add, (
        f"positive control AddPermission did not appear in the policy: {policy_after_add!r}"
    )
    sqs.remove_permission(QueueUrl=sibling, Label=control_label)
    policy_after_remove = (
        sqs.get_queue_attributes(QueueUrl=sibling, AttributeNames=["Policy"])
        .get("Attributes", {})
        .get("Policy")
    )
    assert policy_after_remove is None or control_label not in policy_after_remove, (
        f"positive control RemovePermission left the label in the policy: {policy_after_remove!r}"
    )

    # The doomed queue carries a permission at the moment it is deleted.
    doomed_label = ctx.unique_name("sim2realDoomedLabel")
    sqs.add_permission(
        QueueUrl=doomed, Label=doomed_label, AWSAccountIds=[account], Actions=["SendMessage"]
    )
    sqs.delete_queue(QueueUrl=doomed)

    # Deletion is eventually consistent; poll an independent read (GetQueueAttributes, not
    # AddPermission/RemovePermission) until it reports the queue gone, then hold both
    # permission operations to the same refusal.
    read_err: dict = {}
    deadline = time.monotonic() + _SETTLE_S
    while time.monotonic() < deadline:
        try:
            sqs.get_queue_attributes(QueueUrl=doomed, AttributeNames=["QueueArn"])
        except ClientError as exc:
            read_err = exc.response.get("Error", {})
            break
        time.sleep(3)
    assert (read_err.get("Code"), read_err.get("Message")) == (_NOT_FOUND, _NOT_FOUND_MSG), (
        f"GetQueueAttributes on the deleted queue answered {read_err!r} within {_SETTLE_S}s"
    )

    add_err = _error(
        lambda: sqs.add_permission(
            QueueUrl=doomed,
            Label=ctx.unique_name("sim2realLateLabel"),
            AWSAccountIds=[account],
            Actions=["SendMessage"],
        )
    )
    assert (add_err.get("Code"), add_err.get("Message")) == (_NOT_FOUND, _NOT_FOUND_MSG), (
        f"AddPermission on the deleted queue answered {add_err!r}"
    )

    remove_err = _error(lambda: sqs.remove_permission(QueueUrl=doomed, Label=doomed_label))
    assert (remove_err.get("Code"), remove_err.get("Message")) == (_NOT_FOUND, _NOT_FOUND_MSG), (
        f"RemovePermission on the deleted queue answered {remove_err!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
