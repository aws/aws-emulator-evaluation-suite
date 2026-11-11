"""put-environment-variables-exceeds-size-limit-rejected."""
from __future__ import annotations

from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-environment-variables-exceeds-size-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutGraphqlApiEnvironmentVariables rejects more than the documented 50 pairs with
    BadRequestException and persists nothing; a payload within the limit is persisted verbatim.
    """
    appsync = ctx.client("appsync")

    api = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-envvar-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    # Disable client-side validation so the service, not botocore, enforces the limit.
    unvalidated = ctx.client("appsync", config=BotoConfig(parameter_validation=False))
    oversized_vars = {f"VAR{i}": "x" for i in range(60)}  # documented max is 50
    code, message = _error(
        lambda: unvalidated.put_graphql_api_environment_variables(
            apiId=api_id, environmentVariables=oversized_vars
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    rendered = ", ".join(f"{k}={v}" for k, v in oversized_vars.items())
    assert message == (
        f"1 validation error detected: Value '{{{rendered}}}' at 'environmentVariables' failed to satisfy "
        "constraint: Member must have length less than or equal to 50"
    ), f"unexpected BadRequestException message {message!r}"

    # Effect is absent: nothing was persisted, not even a truncated 50-entry subset.
    current = appsync.get_graphql_api_environment_variables(apiId=api_id).get(
        "environmentVariables", {}
    )
    assert current == {}, f"expected no persisted environment variables after rejection, got {current}"

    # The put response could just echo the request, so persistence is checked by a separate read.
    ok_vars = {"OK_VAR": "value"}
    resp = appsync.put_graphql_api_environment_variables(
        apiId=api_id, environmentVariables=ok_vars
    )
    assert resp["environmentVariables"] == ok_vars, (
        f"expected put response to echo {ok_vars}, got {resp['environmentVariables']}"
    )
    persisted = appsync.get_graphql_api_environment_variables(apiId=api_id)["environmentVariables"]
    assert persisted == ok_vars, f"expected {ok_vars} persisted, got {persisted}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
