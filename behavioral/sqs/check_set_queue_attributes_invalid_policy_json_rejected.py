"""set-queue-attributes-invalid-policy-json-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-queue-attributes-invalid-policy-json-rejected"
GROUP = "error-semantics"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetQueueAttributes rejects a syntactically invalid Policy JSON document instead of
    storing it verbatim, while a well-formed policy document still persists."""
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-badpolicy-"),
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    garbage = "{this is not json"
    code, message = _error(
        lambda: sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": garbage})
    )
    assert code == "InvalidAttributeValue", f"expected InvalidAttributeValue, got {code}"
    assert message == "Invalid value for the parameter Policy.", f"unexpected message {message!r}"

    # effect absent: a queue with no policy ever set must still report none - the
    # garbage was rejected outright, not stored verbatim or in some transformed shape
    policy_after = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get(
        "Attributes", {}
    ).get("Policy")
    assert policy_after is None, f"expected no Policy attribute, got {policy_after!r}"

    # positive control: a well-formed policy document is accepted and persisted
    valid_policy = {
        "Version": "2012-10-17",
        "Id": f"{queue_arn}/SIM2REAL",
        "Statement": [
            {
                "Sid": "AllowOwnerSend",
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "SQS:SendMessage",
                "Resource": queue_arn,
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(valid_policy)})
    stored = json.loads(
        sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"][
            "Policy"
        ]
    )
    assert stored["Statement"][0]["Sid"] == "AllowOwnerSend", (
        f"expected the persisted policy Sid to be AllowOwnerSend, got {stored!r}"
    )


def _error(fn):
    """Return (Error.Code, Error.Message) for the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
