"""add-permission-wildcard-action-normalizes-to-sqs-star."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "add-permission-wildcard-action-normalizes-to-sqs-star"
GROUP = "permissions"
SERVICES = ["sqs"]


def _statement(sqs, url, label):
    policy = json.loads(
        sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]["Policy"]
    )
    for stmt in policy["Statement"]:
        if stmt.get("Sid") == label:
            return stmt
    raise AssertionError(f"no statement with Sid {label!r} in {policy['Statement']!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddPermission with Actions=["*"] stores the statement's Action as "SQS:*", distinct from
    the "SQS:<Name>" form a named action produces."""
    sqs = ctx.client("sqs")
    account_id = ctx.account

    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-addpermwc-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    named_label = ctx.unique_name("NamedLabel")
    sqs.add_permission(
        QueueUrl=url, Label=named_label, AWSAccountIds=[account_id], Actions=["SendMessage"]
    )
    named_stmt = _statement(sqs, url, named_label)
    assert named_stmt.get("Action") == "SQS:SendMessage", (
        f"a named action statement read back Action={named_stmt.get('Action')!r}"
    )

    wildcard_label = ctx.unique_name("WildcardLabel")
    sqs.add_permission(
        QueueUrl=url, Label=wildcard_label, AWSAccountIds=[account_id], Actions=["*"]
    )
    wildcard_stmt = _statement(sqs, url, wildcard_label)
    assert wildcard_stmt.get("Action") == "SQS:*", (
        f"a wildcard Actions=['*'] statement read back Action={wildcard_stmt.get('Action')!r}, "
        f"expected 'SQS:*'"
    )
    assert wildcard_stmt.get("Action") != named_stmt.get("Action"), (
        "the wildcard grant's Action must differ from the single named action's Action"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
