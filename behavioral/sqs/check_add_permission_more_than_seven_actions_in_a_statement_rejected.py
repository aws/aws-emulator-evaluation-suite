"""add-permission-more-than-seven-actions-in-a-statement-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-permission-more-than-seven-actions-in-a-statement-rejected"
GROUP = "limits"
SERVICES = ["sqs"]

_SEVEN = ["SendMessage", "ReceiveMessage", "DeleteMessage", "ChangeMessageVisibility",
          "GetQueueAttributes", "GetQueueUrl", "PurgeQueue"]
_EIGHT = _SEVEN + ["DeleteQueue"]


def _error(fn) -> tuple[str, str]:
    """The (code, message) ``fn``'s ClientError carries. An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _sids(sqs, url: str) -> set[str]:
    policy = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get(
        "Attributes", {}
    ).get("Policy")
    if policy is None:
        return set()
    return {s.get("Sid") for s in json.loads(policy)["Statement"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddPermission rejects a statement naming 8 actions; the identical label with 7 actions,
    the documented maximum, is granted and appears in the queue's policy.
    """
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-addpermact-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    assert _sids(sqs, url) == set(), "a fresh queue must carry no policy statements"

    too_many_label = ctx.unique_name("EightActions")
    code, message = _error(
        lambda: sqs.add_permission(
            QueueUrl=url, Label=too_many_label, AWSAccountIds=[account_id], Actions=_EIGHT
        )
    )
    assert code == "OverLimit", f"AddPermission with 8 actions in one statement gave code {code!r}"
    # The trailing space is part of the message AWS returns.
    assert message == "8 Actions were found, maximum allowed is 7. ", (
        f"unexpected refusal message {message!r}"
    )
    assert too_many_label not in _sids(sqs, url), (
        f"the 8-action statement must not have been added; sids are {_sids(sqs, url)!r}"
    )

    seven_label = ctx.unique_name("SevenActions")
    sqs.add_permission(QueueUrl=url, Label=seven_label, AWSAccountIds=[account_id], Actions=_SEVEN)
    sids_after = _sids(sqs, url)
    assert seven_label in sids_after, (
        f"a 7-action statement, the documented maximum, must be granted; sids are {sids_after!r}"
    )
    assert too_many_label not in sids_after, (
        f"the earlier 8-action refusal must still be absent; sids are {sids_after!r}"
    )

    policy = json.loads(
        sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]["Policy"]
    )
    statement = next(s for s in policy["Statement"] if s["Sid"] == seven_label)
    assert sorted(statement["Action"]) == sorted(f"SQS:{a}" for a in _SEVEN), (
        f"granted statement carries actions {statement['Action']!r}"
    )

    sqs.remove_permission(QueueUrl=url, Label=seven_label)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
