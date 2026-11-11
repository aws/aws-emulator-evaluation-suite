"""custom-action-pagination-returns-all-created."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "custom-action-pagination-returns-all-created"
GROUP = "state"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCustomActions with MaxResults=1 paginates via NextToken and the union of all
    pages contains every created action exactly once (no duplication, no truncation)."""
    chatbot = ctx.client("chatbot")
    names = [ctx.unique_name(f"sim2realpg{i}").replace("-", "")[:64] for i in range(3)]
    arns = []
    for name in names:
        arn = chatbot.create_custom_action(
            ActionName=name,
            Definition={"CommandText": f"echo {name}"},
            Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
        )["CustomActionArn"]
        arns.append(arn)
        ctx.on_cleanup(lambda a=arn: _safe_delete(ctx, a))

    seen: list[str] = []
    token = None
    pages = 0
    while True:
        kwargs = {"MaxResults": 1}
        if token:
            kwargs["NextToken"] = token
        resp = chatbot.list_custom_actions(**kwargs)
        page_items = resp.get("CustomActions", [])
        assert len(page_items) <= 1, "MaxResults=1 page returned more than one item"
        seen.extend(page_items)
        pages += 1
        token = resp.get("NextToken")
        if not token or pages > 500:
            break

    for arn in arns:
        matches = [x for x in seen if x == arn]
        assert len(matches) == 1, f"expected exactly one occurrence of {arn} across pages, saw {len(matches)}"


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
