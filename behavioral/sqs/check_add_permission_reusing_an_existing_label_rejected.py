"""add-permission-reusing-an-existing-label-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-permission-reusing-an-existing-label-rejected"
GROUP = "error-semantics"
SERVICES = ["sqs"]


def _error(fn):
    """(code, message) of the refusal ``fn`` raises; an unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _statements(sqs, url) -> dict:
    policy = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]["Policy"]
    statements = json.loads(policy)["Statement"]
    return {s["Sid"]: (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])
            for s in statements}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddPermission reusing a Label already on the queue's policy is rejected and leaves that
    statement's Action unchanged, while a fresh Label is still accepted."""
    sqs = ctx.client("sqs")
    account_id = ctx.account

    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-addperm2-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    label = ctx.unique_name("Perm")
    sqs.add_permission(
        QueueUrl=url, Label=label, AWSAccountIds=[account_id], Actions=["SendMessage"]
    )
    before = _statements(sqs, url)
    assert before.get(label) == ["SQS:SendMessage"], f"first AddPermission read back {before!r}"

    code, message = _error(lambda: sqs.add_permission(
        QueueUrl=url, Label=label, AWSAccountIds=[account_id], Actions=["ReceiveMessage"]
    ))
    assert code == "InvalidParameterValue", f"reusing an existing Label gave {(code, message)!r}"
    assert message == (
        f"Value {label} for parameter Label is invalid. Reason: Already exists."
    ), f"reusing an existing Label gave message {message!r}"

    after = _statements(sqs, url)
    assert after.get(label) == ["SQS:SendMessage"], (
        f"the refused re-add changed the existing statement's Action: {after!r}"
    )

    fresh_label = ctx.unique_name("PermFresh")
    sqs.add_permission(
        QueueUrl=url, Label=fresh_label, AWSAccountIds=[account_id], Actions=["ReceiveMessage"]
    )
    final = _statements(sqs, url)
    assert final.get(fresh_label) == ["SQS:ReceiveMessage"], (
        f"a fresh Label after the refusal was not accepted: {final!r}"
    )
    assert final.get(label) == ["SQS:SendMessage"], (
        f"the original statement changed after the fresh add: {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
