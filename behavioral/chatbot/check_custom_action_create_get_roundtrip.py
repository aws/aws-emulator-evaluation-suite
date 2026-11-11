"""custom-action-create-get-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-action-create-get-roundtrip"
GROUP = "lifecycle"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCustomAction persists Definition/ActionName/AliasName exactly as supplied."""
    chatbot = ctx.client("chatbot")
    action_name = ctx.unique_name("sim2real-ca-")
    resp = chatbot.create_custom_action(
        ActionName=action_name,
        Definition={"CommandText": "echo hello"},
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
    )
    arn = resp["CustomActionArn"]
    ctx.on_cleanup(lambda: chatbot.delete_custom_action(CustomActionArn=arn))

    got = chatbot.get_custom_action(CustomActionArn=arn)["CustomAction"]
    assert got["CustomActionArn"] == arn, f"expected CustomActionArn={arn!r}, got {got['CustomActionArn']!r}"
    assert got["ActionName"] == action_name, f"expected ActionName={action_name!r}, got {got['ActionName']!r}"
    assert got["Definition"]["CommandText"] == "echo hello", (
        f"expected CommandText='echo hello', got {got['Definition']['CommandText']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
