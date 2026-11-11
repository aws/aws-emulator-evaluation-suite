"""list-connections-reflects-created-and-provider-filter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-connections-reflects-created-and-provider-filter"
GROUP = "data-plane"
SERVICES = ["codeconnections"]


def _all_connections(cc, **filters) -> list:
    items: list = []
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 100, **filters}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_connections(**kwargs)
        items.extend(page.get("Connections", []))
        token = page.get("NextToken")
        if not token:
            break
    return items


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListConnections reflects newly created connections and ProviderTypeFilter partitions them."""
    cc = ctx.client("codeconnections")
    gh_name = ctx.unique_name("sim2realgh-")[-32:]
    bb_name = ctx.unique_name("sim2realbb-")[-32:]

    tags = [{"Key": "owner", "Value": "sim2real"}]
    gh_arn = cc.create_connection(ConnectionName=gh_name, ProviderType="GitHub", Tags=tags)[
        "ConnectionArn"
    ]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=gh_arn))
    bb_arn = cc.create_connection(ConnectionName=bb_name, ProviderType="Bitbucket", Tags=tags)[
        "ConnectionArn"
    ]
    ctx.on_cleanup(lambda: cc.delete_connection(ConnectionArn=bb_arn))

    all_arns = {c["ConnectionArn"] for c in _all_connections(cc)}
    assert gh_arn in all_arns, f"expected {gh_arn} in unfiltered list, got {all_arns}"
    assert bb_arn in all_arns, f"expected {bb_arn} in unfiltered list, got {all_arns}"

    github_arns = {c["ConnectionArn"] for c in _all_connections(cc, ProviderTypeFilter="GitHub")}
    assert gh_arn in github_arns, f"expected GitHub connection {gh_arn} in {github_arns}"
    assert bb_arn not in github_arns, (
        f"expected Bitbucket connection {bb_arn} excluded from GitHub filter, got {github_arns}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
