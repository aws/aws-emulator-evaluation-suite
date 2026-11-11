"""update-type-invalid-sdl-rejected."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-type-invalid-sdl-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]


def _norm(sdl: str) -> str:
    """AppSync round-trips SDL through its own pretty-printer (re-indents, may reorder
    whitespace) -- collapse all whitespace so we compare content, not formatting."""
    return re.sub(r"\s+", "", sdl)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateType with a malformed SDL definition (an unterminated type block) is rejected with
    BadRequestException, and GetType still returns the type's prior, valid definition unchanged --
    not a half-applied schema fragment."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    original_def = "type Widget {\n  id: ID\n  name: String\n}\n"
    appsync.create_type(apiId=api_id, definition=original_def, format="SDL")
    ctx.on_cleanup(lambda: appsync.delete_type(apiId=api_id, typeName="Widget"))

    got = appsync.get_type(apiId=api_id, typeName="Widget", format="SDL")["type"]
    assert _norm(got["definition"]) == _norm(original_def), (
        f"GetType definition {got['definition']!r} does not match what was created {original_def!r}"
    )
    baseline_def = got["definition"]

    malformed_def = "type Widget {\n  id: ID\n  name: String\n"  # missing closing brace
    code, msg = _error(
        lambda: appsync.update_type(
            apiId=api_id, typeName="Widget", definition=malformed_def, format="SDL"
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    assert msg == "Unable to parse provided type definition.", f"unexpected message: {msg!r}"

    # Effect absent: the prior valid definition is still in place, unmodified.
    unchanged = appsync.get_type(apiId=api_id, typeName="Widget", format="SDL")["type"]
    assert _norm(unchanged["definition"]) == _norm(baseline_def), (
        "type definition changed despite the rejected UpdateType call"
    )

    # Positive control: a well-formed update to the same type is accepted and persisted.
    valid_update = "type Widget {\n  id: ID\n  name: String\n  price: Int\n}\n"
    appsync.update_type(apiId=api_id, typeName="Widget", definition=valid_update, format="SDL")
    updated = appsync.get_type(apiId=api_id, typeName="Widget", format="SDL")["type"]
    assert _norm(updated["definition"]) == _norm(valid_update), (
        f"expected valid update to persist as {valid_update!r}, got {updated['definition']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-api-")
    api_id = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real": CHECK, "sim2real:managed": "true"}
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
