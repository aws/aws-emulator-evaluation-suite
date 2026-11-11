"""update-view-rejects-unparsable-sql-and-keeps-the-stored-definition."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-view-rejects-unparsable-sql-and-keeps-the-stored-definition"
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
    """UpdateView with a definition that does not parse as SQL is refused with the parser's error,
    and the view still holds its previous definition and description.
    """
    cwo = ctx.client("cloudwatchomni")
    name = ctx.unique_name("view.sim2realbehavcwo")
    cwo.create_view(name=name, definition="SELECT 1", description="kept")
    ctx.on_cleanup(_teardown(lambda: cwo.delete_view(name=name), "ResourceNotFoundException"))

    code, message = _error(lambda: cwo.update_view(name=name, definition="NOT SQL", description="lost"))
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == (
        "Invalid view definition: sql parser error: Expected: an SQL statement, found: NOT at Line: 1, "
        "Column: 1"
    ), f"unexpected message {message!r}"

    got = cwo.get_view(name=name)
    assert got["definition"] == "SELECT 1", f"the refused update changed the definition: {got['definition']!r}"
    assert got["description"] == "kept", f"the refused update changed the description: {got.get('description')!r}"

    ok = cwo.update_view(name=name, definition="SELECT 2")
    assert ok["definition"] == "SELECT 2", f"a valid update must apply, got {ok['definition']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
