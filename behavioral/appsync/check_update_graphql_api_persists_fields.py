"""update-graphql-api-persists-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-graphql-api-persists-fields"
GROUP = 'graphql-api'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGraphqlApi changes are visible on a subsequent GetGraphqlApi."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"env": "test"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    new_name = ctx.unique_name("sim2real-behav-appsync-api-updated-")

    svc.update_graphql_api(
        apiId=api_id,
        name=new_name,
        authenticationType="API_KEY",
        xrayEnabled=True,
    )

    got = svc.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert got["name"] == new_name, f"expected persisted name {new_name!r}, got {got['name']!r}"
    assert got.get("xrayEnabled") is True, f"expected xrayEnabled=True, got {got.get('xrayEnabled')!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
