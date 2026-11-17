"""add-permission-nonexistent-queue-rejected."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-permission-nonexistent-queue-rejected"
GROUP = "error-semantics"
SERVICES = ["sqs"]

_ERR_NONEXISTENT_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"
_MSG_NONEXISTENT_QUEUE = "The specified queue does not exist."


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddPermission against a queue URL naming no live queue fails with the NonExistentQueue
    error, and AddPermission against a real queue still succeeds and is readable afterward."""
    sqs = ctx.client("sqs")
    account_id = ctx.account

    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-addpermnx-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    ghost_url = f"{url.rsplit('/', 1)[0]}/{uuid.uuid4().hex[:12]}-ghost"
    err = _client_error(
        lambda: sqs.add_permission(
            QueueUrl=ghost_url, Label="GhostLabel", AWSAccountIds=[account_id], Actions=["SendMessage"]
        )
    )
    assert err.get("Code") == _ERR_NONEXISTENT_QUEUE, (
        f"expected {_ERR_NONEXISTENT_QUEUE} for AddPermission on a queue url naming no live "
        f"queue, got {err!r}"
    )
    assert err.get("Message") == _MSG_NONEXISTENT_QUEUE, f"unexpected refusal message {err!r}"

    # positive control: AddPermission against the real queue succeeds, and the statement is
    # readable through an independent operation, GetQueueAttributes.
    label = ctx.unique_name("RealLabel")
    sqs.add_permission(QueueUrl=url, Label=label, AWSAccountIds=[account_id], Actions=["SendMessage"])
    policy = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]["Policy"]
    sids = {stmt.get("Sid") for stmt in json.loads(policy)["Statement"]}
    assert label in sids, f"expected {label!r} in the real queue's policy statements, got {sids!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
