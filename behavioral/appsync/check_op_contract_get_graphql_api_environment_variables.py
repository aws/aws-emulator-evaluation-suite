"""op-contract-getGraphqlApiEnvironmentVariables."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getGraphqlApiEnvironmentVariables"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGraphqlApiEnvironmentVariables round-trips what PutGraphqlApiEnvironmentVariables wrote,
    reflects a subsequent overwrite rather than a stale value, and 404s on an unknown apiId."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    env_vars = {"BEHAVIORAL_CHECK": "1", "STAGE": "sim2real"}
    appsync.put_graphql_api_environment_variables(apiId=api_id, environmentVariables=env_vars)

    got = appsync.get_graphql_api_environment_variables(apiId=api_id)["environmentVariables"]
    assert got == env_vars, f"expected {env_vars}, got {got}"

    # Overwrite and re-verify the round trip reflects the latest Put, not a stale value.
    env_vars_2 = {"BEHAVIORAL_CHECK": "2", "STAGE": "sim2real-overwritten"}
    appsync.put_graphql_api_environment_variables(apiId=api_id, environmentVariables=env_vars_2)
    got2 = appsync.get_graphql_api_environment_variables(apiId=api_id)["environmentVariables"]
    assert got2 == env_vars_2, f"expected {env_vars_2}, got {got2}"

    code, msg = _error(
        lambda: appsync.get_graphql_api_environment_variables(apiId="does_not_exist_1234")
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert msg == "API not found.", f"unexpected message: {msg!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-gql-")
    api = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real-check": CHECK},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
