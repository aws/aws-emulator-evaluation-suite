"""create-view-retry-with-same-client-token-is-refused-as-a-conflict."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-view-retry-with-same-client-token-is-refused-as-a-conflict"
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
    """Repeating CreateView with the clientToken of a view that already exists answers the name
    conflict rather than the original view, and the stored view is the first request's.
    """
    cwo = ctx.client("cloudwatchomni")
    name = ctx.unique_name("view.sim2realbehavcwo")
    token = str(uuid.uuid4())
    first = cwo.create_view(name=name, definition="SELECT 1", description="first", clientToken=token)
    ctx.on_cleanup(_teardown(lambda: cwo.delete_view(name=name), "ResourceNotFoundException"))
    assert first["name"] == name, f"expected {name!r}, got {first.get('name')!r}"

    code, message = _error(
        lambda: cwo.create_view(name=name, definition="SELECT 1", description="first", clientToken=token)
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}: {message!r}"
    assert message == f"View already exists: {name}", f"unexpected message {message!r}"

    got = cwo.get_view(name=name)
    assert got["arn"] == first["arn"], "the retried create must not mint a second view"
    assert got["definition"] == "SELECT 1", f"expected 'SELECT 1', got {got['definition']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
