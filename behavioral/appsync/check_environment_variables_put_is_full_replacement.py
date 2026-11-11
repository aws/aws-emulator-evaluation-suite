"""environment-variables-put-is-full-replacement."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "environment-variables-put-is-full-replacement"
GROUP = 'environment-variables'
SERVICES = ['appsync']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGraphqlApiEnvironmentVariables OVERWRITES the whole map (it is not a merge),
    and Get reflects each write; an empty map clears all variables."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)["apiId"]

    def _get():
        return appsync.get_graphql_api_environment_variables(apiId=api_id).get(
            "environmentVariables", {}
        )

    assert _get() == {}, "expected no environment variables on a new API"

    put1 = appsync.put_graphql_api_environment_variables(
        apiId=api_id, environmentVariables={"FIRST": "one", "SECOND": "two"}
    ).get("environmentVariables", {})
    assert put1 == {"FIRST": "one", "SECOND": "two"}, f"expected Put to echo the written map, got {put1}"
    got1 = _get()
    assert got1 == {"FIRST": "one", "SECOND": "two"}, f"expected {{'FIRST': 'one', 'SECOND': 'two'}}, got {got1}"

    # full replacement, NOT a merge: SECOND must disappear
    put2 = appsync.put_graphql_api_environment_variables(
        apiId=api_id, environmentVariables={"THIRD": "three"}
    ).get("environmentVariables", {})
    assert put2 == {"THIRD": "three"}, f"expected Put to echo the written map, got {put2}"
    got2 = _get()
    assert got2 == {"THIRD": "three"}, f"Put must replace, not merge; got {got2}"

    cleared = appsync.put_graphql_api_environment_variables(
        apiId=api_id, environmentVariables={}
    ).get("environmentVariables", {})
    assert cleared == {}, f"expected Put with an empty map to clear all variables, got {cleared}"
    got3 = _get()
    assert got3 == {}, f"expected no environment variables after clearing, got {got3}"


def _create_graphql_api(ctx) -> dict:
    """An API_KEY-auth GraphQL API. Sub-resources (data sources, functions,
    resolvers, types) are removed with their owning apiId, so only the API
    itself needs a teardown."""
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": "environment-variables-put-is-full-replacement"},
    )
    api = resp["graphqlApi"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api["apiId"]))
    return api


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
