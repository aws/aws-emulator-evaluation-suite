"""create-type-duplicate-name-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-type-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]

_DEFINITION = "type DupeType {\n  id: ID\n}\n"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateType rejects a second attempt to create a type with a name that
    already exists on the API instead of silently overwriting/duplicating it."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)
    api_id = api["apiId"]

    first = appsync.create_type(apiId=api_id, definition=_DEFINITION, format="SDL")["type"]
    assert first["name"] == "DupeType", f"expected type named DupeType, got {first!r}"

    error = _error(
        lambda: appsync.create_type(apiId=api_id, definition=_DEFINITION, format="SDL")
    )
    expected = ("BadRequestException", "Type with name DupeType already exists.")
    assert error == expected, f"expected {expected}, got {error}"

    types = appsync.list_types(apiId=api_id, format="SDL")["types"]
    dupe_count = sum(1 for t in types if t["name"] == "DupeType")
    assert dupe_count == 1, f"expected exactly one DupeType, found {dupe_count}: {types}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _create_graphql_api(ctx, auth_type="API_KEY"):
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType=auth_type,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api = resp["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
