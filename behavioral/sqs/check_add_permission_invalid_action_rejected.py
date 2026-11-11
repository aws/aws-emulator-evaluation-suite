"""add-permission-invalid-action-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-permission-invalid-action-rejected"
GROUP = "error-semantics"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddPermission with an action name outside the SQS action set is rejected,
    leaves the queue policy unchanged, and a valid Actions value still works."""
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-addperm-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    policy_before = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get(
        "Attributes", {}
    ).get("Policy")
    assert policy_before is None, "fresh queue should not have a policy yet"

    bad_label = ctx.unique_name("BadActionLabel")
    code, message = _error(
        lambda: sqs.add_permission(
            QueueUrl=url,
            Label=bad_label,
            AWSAccountIds=[account_id],
            Actions=["NotARealSqsAction"],
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected_message = (
        "Value SQS:NotARealSqsAction for parameter ActionName is invalid. "
        "Reason: Please refer to the appropriate WSDL for a list of valid actions."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no policy was created by the rejected call
    policy_after = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get(
        "Attributes", {}
    ).get("Policy")
    assert policy_after is None, "rejected AddPermission must not create a policy statement"

    # positive control: a valid action name is accepted and persisted
    good_label = ctx.unique_name("GoodActionLabel")
    ctx.on_cleanup(lambda: _try(lambda: sqs.remove_permission(QueueUrl=url, Label=good_label)))
    sqs.add_permission(
        QueueUrl=url,
        Label=good_label,
        AWSAccountIds=[account_id],
        Actions=["SendMessage"],
    )
    policy_control = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])[
        "Attributes"
    ]["Policy"]
    assert good_label in policy_control, (
        f"expected {good_label!r} in queue policy after a valid AddPermission, got {policy_control!r}"
    )


def _error(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but call succeeded with {result!r}")


def _try(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
