"""custom-action-create-get-update-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "custom-action-create-get-update-delete-lifecycle"
GROUP = "lifecycle"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCustomAction shows the created AliasName, then the updated one with ActionName unchanged; after
    DeleteCustomAction, Get fails with ResourceNotFoundException "sdk action [<name>] not found for account
    [<account>]" and a second Delete with ResourceNotFoundException and no message."""
    chatbot = ctx.client("chatbot")
    action_name = ctx.unique_name("sim2realcalifecyc").replace("-", "")[:64]

    created = chatbot.create_custom_action(
        ActionName=action_name,
        Definition={"CommandText": "echo alias-before"},
        AliasName="beforealias",
        Tags=[{"TagKey": "sim2real", "TagValue": "custom-action-lifecycle"}],
    )
    arn = created["CustomActionArn"]
    ctx.on_cleanup(lambda: _safe_delete(ctx, arn))

    before = chatbot.get_custom_action(CustomActionArn=arn)["CustomAction"]
    assert before["AliasName"] == "beforealias", (
        f"expected AliasName 'beforealias' right after create, got {before['AliasName']!r}"
    )

    chatbot.update_custom_action(
        CustomActionArn=arn,
        Definition={"CommandText": "echo alias-before"},
        AliasName="afteralias",
    )

    after = chatbot.get_custom_action(CustomActionArn=arn)["CustomAction"]
    assert after["AliasName"] == "afteralias", (
        f"expected AliasName 'afteralias' after update, got {after['AliasName']!r}"
    )
    assert after["ActionName"] == action_name, (
        f"ActionName must stay fixed across UpdateCustomAction, expected "
        f"{action_name!r}, got {after['ActionName']!r}"
    )

    chatbot.delete_custom_action(CustomActionArn=arn)

    code, message = _error(lambda: chatbot.get_custom_action(CustomActionArn=arn))
    assert code == "ResourceNotFoundException", (
        f"expected GetCustomAction on a deleted action to fail with "
        f"ResourceNotFoundException, got {code!r}"
    )
    expected = f"sdk action [{action_name}] not found for account [{ctx.account}]"
    assert message == expected, f"unexpected message={message!r}"

    code2, message2 = _error(lambda: chatbot.delete_custom_action(CustomActionArn=arn))
    assert code2 == "ResourceNotFoundException", (
        f"expected a second DeleteCustomAction on the same arn to fail with "
        f"ResourceNotFoundException, got {code2!r}"
    )
    # AWS's second-delete refusal carries no message at all.
    assert message2 is None, f"unexpected message={message2!r}"


def _safe_delete(ctx, arn: str) -> None:
    chatbot = ctx.client("chatbot")
    try:
        chatbot.delete_custom_action(CustomActionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return the (code, message) it is refused with. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
