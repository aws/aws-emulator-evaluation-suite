"""list-control-mappings-max-results-over-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-control-mappings-max-results-over-limit-rejected"
GROUP = "limits"
SERVICES = ["controlcatalog"]

_OVER_LIMIT = (
    "ValidationException",
    "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
    "Member must have value less than or equal to 1000",
)


def expect_error(fn, code: str, message: str) -> None:
    """Assert fn() raises exactly (code, message); an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListControlMappings rejects MaxResults past its documented 1000-item ceiling with
    ValidationException, while the ceiling value itself still succeeds."""
    cc = ctx.client("controlcatalog")

    at_ceiling = cc.list_control_mappings(MaxResults=1000)
    assert "ControlMappings" in at_ceiling, (
        f"expected a ControlMappings page at the documented ceiling, got keys {sorted(at_ceiling)!r}"
    )

    expect_error(lambda: cc.list_control_mappings(MaxResults=1001), *_OVER_LIMIT)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
