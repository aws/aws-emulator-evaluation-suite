"""update-view-description-only-preserves-definition-and-identity."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-view-description-only-preserves-definition-and-identity"
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateView with only a description changes the description and updatedAt, and leaves the
    definition, type, ARN and createdAt exactly as they were.
    """
    cwo = ctx.client("cloudwatchomni")
    name = ctx.unique_name("view.sim2realbehavcwo")
    created = cwo.create_view(name=name, definition="SELECT 1 AS a", description="before")
    ctx.on_cleanup(_teardown(lambda: cwo.delete_view(name=name), "ResourceNotFoundException"))

    updated = cwo.update_view(name=name, description="after")
    assert updated["description"] == "after", f"expected 'after', got {updated.get('description')!r}"
    assert updated["definition"] == "SELECT 1 AS a", f"definition changed: {updated['definition']!r}"

    got = cwo.get_view(name=name)
    assert got["description"] == "after", f"expected 'after', got {got.get('description')!r}"
    assert got["definition"] == "SELECT 1 AS a", f"definition changed: {got['definition']!r}"
    assert got["type"] == "USER", f"expected USER, got {got['type']!r}"
    assert got["arn"] == created["arn"], "the ARN must not change on update"
    assert got["createdAt"] == created["createdAt"], (
        f"createdAt moved: {created['createdAt']!r} -> {got['createdAt']!r}"
    )
    assert got["updatedAt"] >= created["updatedAt"], (
        f"updatedAt went backwards: {created['updatedAt']!r} -> {got['updatedAt']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
