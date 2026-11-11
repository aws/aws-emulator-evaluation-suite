"""create-type-duplicate-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-type-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateType is rejected with BadRequestException when the type name already exists."""
    appsync = ctx.client("appsync")
    api = _create_graphql_api(ctx)

    type_name = _safe_name(ctx, "sim2real_type_")
    definition = f"type {type_name} {{\n  id: String\n}}\n"
    first = appsync.create_type(apiId=api["apiId"], definition=definition, format="SDL")["type"]
    ctx.on_cleanup(
        lambda: appsync.delete_type(apiId=api["apiId"], typeName=type_name)
    )
    # positive control: the first create actually succeeded and registered the type
    assert first["name"] == type_name, f"expected {type_name!r}, got {first['name']!r}"

    error = _error(
        lambda: appsync.create_type(apiId=api["apiId"], definition=definition, format="SDL")
    )
    expected = ("BadRequestException", f"Type with name {type_name} already exists.")
    assert error == expected, f"expected {expected}, got {error}"

    # the original type definition survived the rejected duplicate create
    got = appsync.get_type(apiId=api["apiId"], typeName=type_name, format="SDL")["type"]
    assert got["name"] == type_name
    assert "id: String" in got["definition"], (
        f"expected original field preserved, got {got['definition']!r}"
    )

    # independent read at the destination: exactly one type of this name is registered,
    # not silently duplicated or overwritten
    listed = appsync.list_types(apiId=api["apiId"], format="SDL")["types"]
    dupe_count = sum(1 for t in listed if t["name"] == type_name)
    assert dupe_count == 1, f"expected exactly one {type_name!r}, found {dupe_count}: {listed}"


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_graphql_api(ctx, auth_type: str = "API_KEY") -> dict:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(
        name=name,
        authenticationType=auth_type,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api = resp["graphqlApi"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api["apiId"]))
    return api


def _safe_name(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
