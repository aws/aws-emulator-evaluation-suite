"""op-tag-and-permission-validation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-tag-and-permission-validation-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

# Exact messages real SQS returns for these refusals.
MSG_TAG = 'Tag values must be between 0 and 256 characters in length.'
MSG_LABEL = "Value NoSuchLabel for parameter Label is invalid. Reason: can't find label on existing policy."
MSG_ACTION = 'Value SQS:NotARealAction for parameter ActionName is invalid. Reason: Please refer to the appropriate WSDL for a list of valid actions.'


def _client_error(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


def _try(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagQueue with an oversized tag value, RemovePermission for an unknown Label, and
    AddPermission with an invalid action are each rejected without side effect, and the
    same operation still succeeds with valid input."""
    sqs = ctx.client("sqs")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    # --- TagQueue: an oversized tag value is rejected (distinct from the oversized-key
    oversized_value = "v" * 300
    err_tag = _client_error(lambda: sqs.tag_queue(QueueUrl=url, Tags={"Environment": oversized_value}))
    assert err_tag.get("Code") == "InvalidParameterValue", f"got {err_tag!r}"
    assert err_tag.get("Message") == MSG_TAG, f"got {err_tag!r}"
    tags_after_reject = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
    assert "Environment" not in tags_after_reject, "rejected oversized tag value was still stored"
    sqs.tag_queue(QueueUrl=url, Tags={"Environment": "sim2real-test"})
    ctx.on_cleanup(lambda: _try(lambda: sqs.untag_queue(QueueUrl=url, TagKeys=["Environment"])))
    tags_after_control = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
    assert tags_after_control.get("Environment") == "sim2real-test", "valid tag was not persisted"

    # --- RemovePermission: an unknown Label is rejected, the real statement is untouched ---
    existing_label = ctx.unique_name("ExistingLabel")
    sqs.add_permission(QueueUrl=url, Label=existing_label, AWSAccountIds=[account], Actions=["SendMessage"])
    err_missing = _client_error(lambda: sqs.remove_permission(QueueUrl=url, Label="NoSuchLabel"))
    assert err_missing.get("Code") == "InvalidParameterValue", f"got {err_missing!r}"
    assert err_missing.get("Message") == MSG_LABEL, f"got {err_missing!r}"
    policy_after_reject = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get("Attributes", {}).get("Policy")
    assert policy_after_reject is not None and existing_label in policy_after_reject, (
        "rejected RemovePermission disturbed the existing statement"
    )
    sqs.remove_permission(QueueUrl=url, Label=existing_label)
    policy_after_control = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get("Attributes", {}).get("Policy")
    assert policy_after_control is None or existing_label not in policy_after_control, (
        "RemovePermission with a real label did not take effect"
    )

    # --- AddPermission: an invalid Action name is rejected without creating a statement ---
    bad_label = ctx.unique_name("BadActionLabel")
    err_action = _client_error(
        lambda: sqs.add_permission(
            QueueUrl=url, Label=bad_label, AWSAccountIds=[account], Actions=["NotARealAction"]
        )
    )
    assert err_action.get("Code") == "InvalidParameterValue", f"got {err_action!r}"
    assert err_action.get("Message") == MSG_ACTION, f"got {err_action!r}"
    policy_after_action_reject = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"]).get("Attributes", {}).get("Policy")
    assert policy_after_action_reject is None or bad_label not in policy_after_action_reject, (
        "rejected AddPermission created a statement"
    )
    good_label = ctx.unique_name("GoodActionLabel")
    ctx.on_cleanup(lambda: _try(lambda: sqs.remove_permission(QueueUrl=url, Label=good_label)))
    sqs.add_permission(QueueUrl=url, Label=good_label, AWSAccountIds=[account], Actions=["SendMessage"])
    policy_control = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]["Policy"]
    assert good_label in policy_control, "AddPermission with a valid action did not persist"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
