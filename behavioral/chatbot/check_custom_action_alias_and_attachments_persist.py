"""custom-action-alias-and-attachments-persist."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-action-alias-and-attachments-persist"
GROUP = "lifecycle"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AliasName and Attachments supplied at creation round-trip through GetCustomAction."""
    chatbot = ctx.client("chatbot")
    alias = ctx.unique_name("sim2real-alias-")[:30]
    attachment = {
        "NotificationType": "CUSTOM",
        "ButtonText": "Run it",
    }
    arn = chatbot.create_custom_action(
        ActionName=ctx.unique_name("sim2real-ca-"),
        AliasName=alias,
        Attachments=[attachment],
        Definition={"CommandText": "echo aliased"},
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: chatbot.delete_custom_action(CustomActionArn=arn))

    got = chatbot.get_custom_action(CustomActionArn=arn)["CustomAction"]
    assert got["AliasName"] == alias, f"expected AliasName {alias!r}, got {got.get('AliasName')!r}"
    assert len(got["Attachments"]) == 1, (
        f"expected exactly 1 attachment to persist, got {len(got['Attachments'])}"
    )
    persisted = got["Attachments"][0]
    assert persisted["ButtonText"] == "Run it", (
        f"expected ButtonText 'Run it', got {persisted.get('ButtonText')!r}"
    )
    assert persisted["NotificationType"] == "CUSTOM", (
        f"expected NotificationType 'CUSTOM', got {persisted.get('NotificationType')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
