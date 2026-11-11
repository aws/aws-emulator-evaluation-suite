"""add-permission-over-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-permission-over-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddPermission rejects a 21st statement once a queue policy already holds the 20-label maximum,
    and the identical call succeeds again once a slot is freed."""
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-"),
        tags={"sim2real": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    labels = [f"Perm{i}" for i in range(20)]
    for label in labels:
        sqs.add_permission(QueueUrl=url, Label=label, AWSAccountIds=[account_id], Actions=["SendMessage"])

    policy_attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]
    import json as _json

    statement_sids = {s.get("Sid") for s in _json.loads(policy_attrs["Policy"])["Statement"]}
    assert set(labels).issubset(statement_sids), (
        f"expected all 20 positive-control labels {labels} present, got {statement_sids}"
    )

    code, message = _error(
        lambda: sqs.add_permission(
            QueueUrl=url, Label="OneTooMany", AWSAccountIds=[account_id], Actions=["SendMessage"]
        )
    )
    assert code == "OverLimit", f"expected OverLimit for a 21st statement, got {code}"
    # The trailing space is part of the message AWS returns.
    assert message == "21 Statements were found, maximum allowed is 20. ", (
        f"unexpected refusal message {message!r}"
    )

    # Effect absent: the 21st label must not have been added.
    policy_after = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]["Policy"]
    sids_after = {s.get("Sid") for s in _json.loads(policy_after)["Statement"]}
    assert "OneTooMany" not in sids_after, f"OneTooMany must be absent from {sids_after}"
    assert len(sids_after) == 20, f"expected 20 statements to remain, got {len(sids_after)}"

    # Restore: free exactly one slot and demand the identical call now succeeds.
    sqs.remove_permission(QueueUrl=url, Label=labels[0])
    sqs.add_permission(QueueUrl=url, Label="OneTooMany", AWSAccountIds=[account_id], Actions=["SendMessage"])
    policy_restored = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]["Policy"]
    sids_restored = {s.get("Sid") for s in _json.loads(policy_restored)["Statement"]}
    assert "OneTooMany" in sids_restored, f"expected OneTooMany present after freeing a slot, got {sids_restored}"
    assert labels[0] not in sids_restored, f"expected {labels[0]} removed, got {sids_restored}"

    for label in labels[1:] + ["OneTooMany"]:
        sqs.remove_permission(QueueUrl=url, Label=label)


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the call to raise a ClientError, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
