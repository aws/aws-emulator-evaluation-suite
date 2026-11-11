"""put-environment-variables-size-limit-rejected."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "put-environment-variables-size-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGraphqlApiEnvironmentVariables rejects a map over the 50-pair limit with BadRequestException
    and leaves the variables stored before it untouched."""
    appsync = ctx.client("appsync")

    api_name = ctx.unique_name("sim2real-appsync-envvar-")
    api_id = appsync.create_graphql_api(
        name=api_name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    # Positive control: a valid, within-limits payload is accepted and round-trips.
    valid_vars = {"USER_TABLE": "users_prod", "DEBUG": "true"}
    put_resp = appsync.put_graphql_api_environment_variables(apiId=api_id, environmentVariables=valid_vars)
    assert put_resp["environmentVariables"] == valid_vars, put_resp
    got = appsync.get_graphql_api_environment_variables(apiId=api_id)["environmentVariables"]
    assert got == valid_vars, f"expected positive control to round-trip, got {got}"

    # Break the precondition: exceed the documented 50 key-value pair limit.
    oversized_vars = {f"VAR{i}": f"value{i}" for i in range(51)}
    assert len(oversized_vars) == 51, "test data itself must exceed the 50-entry limit by exactly 1"
    rejected_code, rejected_message = _error(
        lambda: appsync.put_graphql_api_environment_variables(apiId=api_id, environmentVariables=oversized_vars)
    )
    assert rejected_code == "BadRequestException", (
        f"expected BadRequestException for a 51-entry environment variable map, got {rejected_code}"
    )
    rendered = ", ".join(f"{k}={v}" for k, v in oversized_vars.items())
    assert rejected_message == (
        f"1 validation error detected: Value '{{{rendered}}}' at 'environmentVariables' failed to satisfy "
        "constraint: Member must have length less than or equal to 50"
    ), f"unexpected BadRequestException message {rejected_message!r}"

    # The rejected call must not have overwritten the previously stored variables.
    unchanged = appsync.get_graphql_api_environment_variables(apiId=api_id)["environmentVariables"]
    assert unchanged == valid_vars, f"expected environment variables unchanged after rejection, got {unchanged}"


def _error(fn):
    """Call fn(); return its botocore error code and message.
    An unexpected success raises: accepting what AWS refuses is a finding, not a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected PutGraphqlApiEnvironmentVariables to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
