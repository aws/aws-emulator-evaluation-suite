"""list-connectors-malformed-next-token-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-connectors-malformed-next-token-rejected"
GROUP = "validation"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConnectors rejects a NextToken that is not a token it ever issued with
    ValidationException, and a call without any NextToken in the same file still succeeds
    normally.
    """
    pcad = ctx.client("pca-connector-ad")

    code, message = _error_code(
        lambda: pcad.list_connectors(NextToken="this-is-not-a-real-pagination-token")
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a NextToken it never issued, got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value 'this-is-not-a-real-pagination-token' at "
        "'nextToken' failed to satisfy constraint: Member must satisfy regular expression "
        "pattern: (?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2}==|[A-Za-z0-9_-]{3}=)?"
    ), message

    # positive control: a call with no NextToken at all still succeeds normally.
    control = pcad.list_connectors()
    assert "Connectors" in control, (
        f"expected a healthy ListConnectors response to include Connectors, got keys "
        f"{sorted(control.keys())!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        return type(exc).__name__, str(exc)
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
