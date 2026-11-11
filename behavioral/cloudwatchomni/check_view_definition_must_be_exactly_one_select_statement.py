"""view-definition-must-be-exactly-one-select-statement."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "view-definition-must-be-exactly-one-select-statement"
GROUP = "views"
SERVICES = ["cloudwatchomni"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn()`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A view definition that is not a SELECT, or holds more than one statement, is refused with
    its own message and creates nothing, while a single SELECT is stored.
    """
    cwo = ctx.client("cloudwatchomni")
    ddl_name = ctx.unique_name("view.sim2realbehavcwoddl")
    multi_name = ctx.unique_name("view.sim2realbehavcwomulti")
    good_name = ctx.unique_name("view.sim2realbehavcwogood")
    for refused in (ddl_name, multi_name):
        ctx.on_cleanup(_teardown(lambda n=refused: cwo.delete_view(name=n), "ResourceNotFoundException"))

    code, message = _error(lambda: cwo.create_view(name=ddl_name, definition="DROP TABLE default"))
    assert (code, message) == ("ValidationException", "View definition must be a SELECT query"), (
        f"unexpected refusal of a DROP: {code}: {message!r}"
    )
    code, message = _error(lambda: cwo.create_view(name=multi_name, definition="SELECT 1; SELECT 2"))
    assert (code, message) == ("ValidationException", "View definition must contain exactly one SQL statement"), (
        f"unexpected refusal of two statements: {code}: {message!r}"
    )

    cwo.create_view(name=good_name, definition="SELECT 1")
    ctx.on_cleanup(_teardown(lambda: cwo.delete_view(name=good_name), "ResourceNotFoundException"))

    names = set()
    for page in cwo.get_paginator("list_views").paginate(type="USER"):
        names.update(item["name"] for item in page["items"])
    assert good_name in names, f"expected {good_name!r} among the USER views"
    assert ddl_name not in names and multi_name not in names, "a refused view must not be listed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
