"""put-environment-variables-invalid-key-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-environment-variables-invalid-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGraphqlApiEnvironmentVariables with a key that violates the required naming pattern
    (keys must begin with a letter: ``^[A-Za-z]+\\w*$``) is rejected with BadRequestException, and
    the bad key is not partially merged into the API's persisted environment-variable map."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    good_vars = {"GOOD_VAR": "value1"}
    appsync.put_graphql_api_environment_variables(apiId=api_id, environmentVariables=good_vars)
    stored = appsync.get_graphql_api_environment_variables(apiId=api_id)["environmentVariables"]
    assert stored == good_vars, f"expected {good_vars!r} after positive-control put, got {stored!r}"

    bad_vars = {"1_INVALID": "x"}  # violates "keys must begin with a letter"
    code, message = _error(
        lambda: appsync.put_graphql_api_environment_variables(
            apiId=api_id, environmentVariables=bad_vars
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert message == (
        "1 validation error detected: Value '{1_INVALID=x}' at 'environmentVariables' failed to satisfy "
        "constraint: Map keys must satisfy constraint: [Member must have length less than or equal to 64, "
        "Member must have length greater than or equal to 2, "
        "Member must satisfy regular expression pattern: ^[A-Za-z]+\\w*$]"
    ), f"unexpected BadRequestException message {message!r}"

    # Effect absent: the prior valid variables are untouched and the bad key was never persisted.
    stored_after = appsync.get_graphql_api_environment_variables(apiId=api_id)["environmentVariables"]
    assert stored_after == good_vars, f"expected no partial write, got {stored_after!r}"
    assert "1_INVALID" not in stored_after, f"rejected key leaked into persisted map: {stored_after!r}"

    # Positive control: a well-formed write still succeeds afterward.
    good_vars_2 = {"GOOD_VAR": "value1", "GOOD_VAR2": "value2"}
    appsync.put_graphql_api_environment_variables(apiId=api_id, environmentVariables=good_vars_2)
    stored_final = appsync.get_graphql_api_environment_variables(apiId=api_id)["environmentVariables"]
    assert stored_final == good_vars_2, f"expected {good_vars_2!r} after post-rejection put, got {stored_final!r}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-api-")
    api_id = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real": CHECK}
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
