"""custom-action-delete-removes-resource."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-action-delete-removes-resource"
GROUP = "lifecycle"
SERVICES = ["chatbot"]


def _error_info(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteCustomAction, the action is gone: Get fails and a second delete fails too."""
    chatbot = ctx.client("chatbot")
    action_name = ctx.unique_name("sim2real-ca-")
    arn = chatbot.create_custom_action(
        ActionName=action_name,
        Definition={"CommandText": "echo transient"},
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: _delete_if_present(chatbot, arn))
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # Positive control: the action is visible before deletion.
    chatbot.get_custom_action(CustomActionArn=arn)

    chatbot.delete_custom_action(CustomActionArn=arn)

    code, message = _error_info(lambda: chatbot.get_custom_action(CustomActionArn=arn))
    assert code == "ResourceNotFoundException", (
        f"expected GetCustomAction on a deleted action to be ResourceNotFoundException, got {code!r}"
    )
    expected = f"sdk action [{action_name}] not found for account [{account_id}]"
    assert message == expected, f"expected GetCustomAction message {expected!r}, got {message!r}"

    code2, message2 = _error_info(lambda: chatbot.delete_custom_action(CustomActionArn=arn))
    assert code2 == "ResourceNotFoundException", (
        f"expected a second DeleteCustomAction on an already-deleted action to be "
        f"ResourceNotFoundException, got {code2!r}"
    )
    # Real AWS sends this refusal with no message at all.
    assert message2 is None, f"expected the second DeleteCustomAction to carry no message, got {message2!r}"


def _delete_if_present(chatbot, arn):
    try:
        chatbot.delete_custom_action(CustomActionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
