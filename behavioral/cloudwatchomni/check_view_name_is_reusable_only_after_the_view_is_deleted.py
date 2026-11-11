"""view-name-is-reusable-only-after-the-view-is-deleted."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "view-name-is-reusable-only-after-the-view-is-deleted"
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
    """A second CreateView under a live view's name is refused as a conflict and leaves the first
    definition in place; once the view is deleted the same name is free for a new definition.
    """
    cwo = ctx.client("cloudwatchomni")
    name = ctx.unique_name("view.sim2realbehavcwo")
    cwo.create_view(name=name, definition="SELECT 1", description="first")
    ctx.on_cleanup(_teardown(lambda: cwo.delete_view(name=name), "ResourceNotFoundException"))

    code, message = _error(lambda: cwo.create_view(name=name, definition="SELECT 2", description="second"))
    assert code == "ConflictException", f"expected ConflictException, got {code}: {message!r}"
    assert message == f"View already exists: {name}", f"unexpected message {message!r}"

    kept = cwo.get_view(name=name)
    assert kept["definition"] == "SELECT 1", f"the refused create must not replace the definition: {kept['definition']!r}"
    assert kept["description"] == "first", f"expected description 'first', got {kept.get('description')!r}"

    cwo.delete_view(name=name)
    code, message = _error(lambda: cwo.get_view(name=name))
    assert (code, message) == ("ResourceNotFoundException", f"View not found: {name}"), (
        f"expected the deleted view to be gone, got {code}: {message!r}"
    )

    cwo.create_view(name=name, definition="SELECT 2", description="second")
    again = cwo.get_view(name=name)
    assert again["definition"] == "SELECT 2", f"expected the new definition, got {again['definition']!r}"
    assert again["description"] == "second", f"expected 'second', got {again.get('description')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
