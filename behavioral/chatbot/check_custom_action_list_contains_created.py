"""custom-action-list-contains-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-action-list-contains-created"
GROUP = "lifecycle"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCustomActions (paginated) includes a just-created custom action's ARN."""
    chatbot = ctx.client("chatbot")
    arn = chatbot.create_custom_action(
        ActionName=ctx.unique_name("sim2real-ca-"),
        Definition={"CommandText": "echo listed"},
        Tags=[{"TagKey": "env", "TagValue": "sim2real"}],
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: chatbot.delete_custom_action(CustomActionArn=arn))

    found = False
    next_token = None
    pages_seen = 0
    for _ in range(50):
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = chatbot.list_custom_actions(**kwargs)
        pages_seen += 1
        if arn in resp.get("CustomActions", []):
            found = True
            break
        next_token = resp.get("NextToken")
        if not next_token:
            break
    assert found, f"ListCustomActions never returned {arn} across {pages_seen} page(s)"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
