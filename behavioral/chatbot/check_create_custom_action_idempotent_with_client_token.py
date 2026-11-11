"""create-custom-action-idempotent-with-client-token."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-custom-action-idempotent-with-client-token"
GROUP = "state"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCustomAction repeated with the same ClientToken and parameters returns the same
    CustomActionArn rather than a conflict error or a second resource; ListCustomActions lists it once."""
    chatbot = ctx.client("chatbot")
    name = ctx.unique_name("sim2realidem").replace("-", "")[:64]
    client_token = ctx.unique_name("sim2real-token-") + "-" * 33  # satisfies min length 33
    client_token = client_token[:120]
    definition = {"CommandText": "echo idempotent"}
    creation_tags = [{"TagKey": "env", "TagValue": "sim2real"}]

    first = chatbot.create_custom_action(
        ActionName=name, Definition=definition, ClientToken=client_token, Tags=creation_tags
    )
    arn_first = first["CustomActionArn"]
    ctx.on_cleanup(lambda: _safe_delete(ctx, arn_first))

    second = chatbot.create_custom_action(
        ActionName=name, Definition=definition, ClientToken=client_token, Tags=creation_tags
    )
    arn_second = second["CustomActionArn"]

    assert arn_first == arn_second, "idempotent create with same ClientToken returned a different ARN"

    all_actions = _list_all_custom_actions(ctx)
    assert all_actions.count(arn_first) == 1, "idempotent create resulted in a duplicated resource"


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
