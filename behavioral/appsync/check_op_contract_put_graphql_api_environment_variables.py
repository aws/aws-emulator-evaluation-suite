"""op-contract-putGraphqlApiEnvironmentVariables."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-putGraphqlApiEnvironmentVariables"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGraphqlApiEnvironmentVariables persists the exact key/value map, readable back via GetGraphqlApiEnvironmentVariables; a key violating the naming pattern is rejected with BadRequestException and the stored variables are left unchanged."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx, appsync)

    put_resp = appsync.put_graphql_api_environment_variables(
        apiId=api_id, environmentVariables={"MY_STAGE": "test", "FEATURE_FLAG": "on"}
    )
    assert put_resp["environmentVariables"] == {"MY_STAGE": "test", "FEATURE_FLAG": "on"}, (
        f"expected put response to echo the exact map, got {put_resp['environmentVariables']!r}"
    )

    get_resp = appsync.get_graphql_api_environment_variables(apiId=api_id)
    assert get_resp["environmentVariables"] == {"MY_STAGE": "test", "FEATURE_FLAG": "on"}, (
        f"expected independent read to match what was put, got {get_resp['environmentVariables']!r}"
    )

    code, message = _error(
        lambda: appsync.put_graphql_api_environment_variables(
            apiId=api_id, environmentVariables={"1_BAD_KEY": "x"}
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == (
        "1 validation error detected: Value '{1_BAD_KEY=x}' at 'environmentVariables' failed to "
        "satisfy constraint: Map keys must satisfy constraint: [Member must have length less than "
        "or equal to 64, Member must have length greater than or equal to 2, Member must satisfy "
        "regular expression pattern: ^[A-Za-z]+\\w*$]"
    ), message

    # rejected mutation must not have clobbered the previously stored variables
    after = appsync.get_graphql_api_environment_variables(apiId=api_id)["environmentVariables"]
    assert after == {"MY_STAGE": "test", "FEATURE_FLAG": "on"}, (
        f"expected the rejected put to leave prior variables untouched, got {after!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _create_graphql_api(ctx, appsync):
    name = ctx.unique_name("sim2real-appsync-")
    resp = appsync.create_graphql_api(name=name, authenticationType="API_KEY")
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
