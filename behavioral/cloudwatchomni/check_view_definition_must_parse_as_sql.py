"""view-definition-must-parse-as-sql."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "view-definition-must-parse-as-sql"
GROUP = 'views'
SERVICES = ['cloudwatchomni']


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A view round-trips its SQL definition, a non-SQL definition is refused with the parser's
    own error, and the view is paginable and gone once deleted.
    """
    cwo = ctx.client("cloudwatchomni")

    view_name = ctx.unique_name("view.sim2realbehavcwo")
    cwo.create_view(name=view_name, definition="SELECT 1", description="behavioral probe view")
    ctx.on_cleanup(_teardown(lambda: cwo.delete_view(name=view_name), "ResourceNotFoundException"))

    got = cwo.get_view(name=view_name)
    assert got["definition"] == "SELECT 1", f"expected 'SELECT 1', got {got['definition']!r}"
    assert got["type"] == "USER", f"expected USER, got {got['type']!r}"

    bad_name = ctx.unique_name("view.sim2realbehavcwobad")
    code, message = _error(lambda: cwo.create_view(name=bad_name, definition="{}"))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == (
        "Invalid view definition: sql parser error: Expected: an SQL statement, found: { "
        "at Line: 1, Column: 1"
    ), f"unexpected message {message!r}"

    names = set()
    paginator = cwo.get_paginator("list_views")
    for page in paginator.paginate(type="USER"):
        names.update(item["name"] for item in page["items"])
    assert view_name in names, f"expected {view_name!r} among ListViews items, got {sorted(names)[:5]}..."
    assert bad_name not in names, f"the refused view {bad_name!r} must not appear in ListViews"

    cwo.delete_view(name=view_name)
    code, _ = _error(lambda: cwo.get_view(name=view_name))
    assert code == "ResourceNotFoundException", f"expected gone after delete, got {code}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
