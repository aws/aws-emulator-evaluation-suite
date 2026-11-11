"""custom-action-update-changes-persist."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-action-update-changes-persist"
GROUP = "lifecycle"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCustomAction's new Definition is visible on the next GetCustomAction."""
    chatbot = ctx.client("chatbot")
    action_name = ctx.unique_name("sim2real-ca-")
    arn = chatbot.create_custom_action(
        ActionName=action_name,
        Definition={"CommandText": "echo before"},
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: chatbot.delete_custom_action(CustomActionArn=arn))

    before = chatbot.get_custom_action(CustomActionArn=arn)["CustomAction"]
    assert before["Definition"]["CommandText"] == "echo before", (
        f"expected pre-update CommandText='echo before', got {before['Definition']!r}"
    )

    chatbot.update_custom_action(CustomActionArn=arn, Definition={"CommandText": "echo after"})

    after = chatbot.get_custom_action(CustomActionArn=arn)["CustomAction"]
    assert after["Definition"]["CommandText"] == "echo after", (
        f"expected post-update CommandText='echo after', got {after['Definition']!r}"
    )
    # ActionName is immutable via UpdateCustomAction and must be untouched by the update.
    assert after["ActionName"] == action_name, (
        f"expected ActionName unchanged={action_name!r}, got {after['ActionName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
