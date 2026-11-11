"""create-graphql-api-invalid-visibility-value-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-graphql-api-invalid-visibility-value-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGraphqlApi rejects an unsupported visibility value with BadRequestException rather
    than coercing it, while omitting visibility succeeds and defaults to GLOBAL."""
    appsync = ctx.client("appsync")

    bad_api_name = ctx.unique_name("sim2real-appsync-vis-bad-")
    code, message = _error(
        lambda: appsync.create_graphql_api(
            name=bad_api_name,
            authenticationType="API_KEY",
            visibility="NOT_A_REAL_VISIBILITY_VALUE",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Invalid Visibility value specified", f"expected the exact refusal message, got {message!r}"

    # Effect is absent: no API with that name was created anywhere in the account.
    found = False
    paginator = appsync.get_paginator("list_graphql_apis")
    for page in paginator.paginate():
        if any(a["name"] == bad_api_name for a in page.get("graphqlApis", [])):
            found = True
            break
    assert not found, "an API was created despite the invalid visibility value"

    # Positive control: the identical request without visibility succeeds and
    # defaults to GLOBAL, per the documented default.
    ok_api_name = ctx.unique_name("sim2real-appsync-vis-ok-")
    api = appsync.create_graphql_api(
        name=ok_api_name, authenticationType="API_KEY", tags={"sim2real-check": CHECK}
    )["graphqlApi"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api["apiId"]))
    assert api["name"] == ok_api_name, f"expected {ok_api_name!r}, got {api.get('name')!r}"

    # Independent read at the destination: don't trust the create call's own echo.
    fetched = appsync.get_graphql_api(apiId=api["apiId"])["graphqlApi"]
    assert fetched["name"] == ok_api_name, f"expected {ok_api_name!r}, got {fetched.get('name')!r}"
    assert fetched["visibility"] == "GLOBAL", f"expected GLOBAL, got {fetched.get('visibility')!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
