"""update-graphql-api-change-auth-type."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-graphql-api-change-auth-type"
GROUP = 'graphql-api'
SERVICES = ['appsync']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateGraphqlApi can switch authenticationType and the change is reflected on GetGraphqlApi."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]
    assert api["authenticationType"] == "API_KEY", (
        f"expected freshly-created API to have authenticationType API_KEY, got {api['authenticationType']!r}"
    )

    updated = appsync.update_graphql_api(
        apiId=api_id, name=api["name"], authenticationType="AWS_IAM"
    )["graphqlApi"]
    assert updated["authenticationType"] == "AWS_IAM", (
        f"expected update_graphql_api response authenticationType AWS_IAM, got {updated['authenticationType']!r}"
    )

    got = appsync.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert got["authenticationType"] == "AWS_IAM", (
        f"expected independent get_graphql_api read to reflect authenticationType AWS_IAM, got {got['authenticationType']!r}"
    )


def _create_graphql_api(ctx) -> dict:
    """An API_KEY-auth GraphQL API. Sub-resources (data sources, functions,
    resolvers, types) are removed with their owning apiId, so only the API
    itself needs a teardown."""
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api = resp["graphqlApi"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api["apiId"]))
    return api


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
