"""custom-action-list-reflects-create-and-delete."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "custom-action-list-reflects-create-and-delete"
GROUP = "state"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCustomActions includes a newly created action and stops including it after
    deletion, while a sibling action created alongside it remains listed throughout."""
    chatbot = ctx.client("chatbot")
    name_a = ctx.unique_name("sim2reala").replace("-", "")[:64]
    name_b = ctx.unique_name("sim2realb").replace("-", "")[:64]

    arn_a = chatbot.create_custom_action(
        ActionName=name_a,
        Definition={"CommandText": "echo a"},
        Tags=[{"TagKey": "env", "TagValue": "sim2real"}],
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: _safe_delete(ctx, arn_a))
    arn_b = chatbot.create_custom_action(
        ActionName=name_b,
        Definition={"CommandText": "echo b"},
        Tags=[{"TagKey": "env", "TagValue": "sim2real"}],
    )["CustomActionArn"]
    ctx.on_cleanup(lambda: _safe_delete(ctx, arn_b))

    listed = _list_all_custom_actions(ctx)
    assert arn_a in listed and arn_b in listed, (
        f"expected both {arn_a} and {arn_b} in ListCustomActions, got {listed}"
    )

    chatbot.delete_custom_action(CustomActionArn=arn_a)

    listed_after = _list_all_custom_actions(ctx)
    assert arn_a not in listed_after, "deleted custom action still present in ListCustomActions"
    assert arn_b in listed_after, "sibling custom action unexpectedly disappeared"


def _list_all_custom_actions(ctx) -> list[str]:
    chatbot = ctx.client("chatbot")
    out: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = chatbot.list_custom_actions(**kwargs)
        out.extend(resp.get("CustomActions", []))
        token = resp.get("NextToken")
        if not token:
            break
    return out


def _safe_delete(ctx, arn: str) -> None:
    chatbot = ctx.client("chatbot")
    try:
        chatbot.delete_custom_action(CustomActionArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
