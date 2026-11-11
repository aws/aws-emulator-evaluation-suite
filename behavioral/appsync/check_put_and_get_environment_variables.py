"""put-and-get-environment-variables."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-and-get-environment-variables"
GROUP = 'environment-variables'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGraphqlApiEnvironmentVariables values are returned verbatim by GetGraphqlApiEnvironmentVariables."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    env_vars = {"TEST_ENV_VAR": "value1", "SECOND_ENV_VAR": "value2"}
    svc.put_graphql_api_environment_variables(apiId=api_id, environmentVariables=env_vars)

    got = svc.get_graphql_api_environment_variables(apiId=api_id)["environmentVariables"]
    assert got == env_vars, f"expected {env_vars} verbatim, got {got}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
