"""op-contract-create-type."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-type"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateType stores a real SDL type definition and rejects a malformed definition."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)
    definition = "type Query {\n  ping: String\n}"

    created = appsync.create_type(apiId=api_id, definition=definition, format="SDL")["type"]
    ctx.on_cleanup(lambda: appsync.delete_type(apiId=api_id, typeName="Query"))

    assert created["name"] == "Query", f"expected name Query, got {created['name']!r}"
    assert created["format"] == "SDL", f"expected format SDL, got {created['format']!r}"
    assert "ping: String" in created["definition"], (
        f"expected 'ping: String' in definition, got {created['definition']!r}"
    )
    assert created["arn"].endswith("types/Query"), (
        f"expected arn to end with types/Query, got {created['arn']!r}"
    )

    fetched = appsync.get_type(apiId=api_id, typeName="Query", format="SDL")["type"]
    assert fetched["name"] == "Query", f"expected name Query, got {fetched['name']!r}"
    assert "ping" in fetched["definition"], (
        f"expected 'ping' in definition, got {fetched['definition']!r}"
    )

    listed = appsync.list_types(apiId=api_id, format="SDL")["types"]
    assert any(t["name"] == "Query" for t in listed), (
        f"expected Query in list_types, got {[t['name'] for t in listed]!r}"
    )

    # Error boundary: unbalanced braces is not valid SDL.
    malformed = "type Broken {\n  field: String"
    code, message = _error(
        lambda: appsync.create_type(apiId=api_id, definition=malformed, format="SDL")
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    assert message == "Unable to parse provided type definition.", message

    # The rejected create must not have registered a "Broken" type.
    listed_after = appsync.list_types(apiId=api_id, format="SDL")["types"]
    assert not any(t["name"] == "Broken" for t in listed_after), (
        f"expected no Broken type after rejected create, got "
        f"{[t['name'] for t in listed_after]!r}"
    )


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK},
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
