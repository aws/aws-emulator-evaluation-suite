"""list-controls-implementation-types-filter-overflow-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-controls-implementation-types-filter-overflow-rejected"
GROUP = "error-semantics"
SERVICES = ["controlcatalog"]

_TYPES_LENGTH_MESSAGE = (
    "1 validation error detected: Value at 'filter.implementations.types' failed to satisfy constraint: "
    "Member must have length less than or equal to 1"
)


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises, so an emulator
    accepting what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects a 2-element Implementations.Types filter, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Filter.Implementations.Types is capped at 1 element; a 2-element list is rejected, while a
    single-element filter is accepted and correctly scopes results to that implementation type."""
    cc = ctx.client("controlcatalog")

    code, message = _error_code(
        lambda: cc.list_controls(
            MaxResults=10,
            Filter={
                "Implementations": {
                    "Types": ["AWS::Config::ConfigRule", "AWS::SecurityHub::SecurityControl"]
                }
            },
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a 2-element Implementations.Types filter, got {code}"
    )
    assert message == _TYPES_LENGTH_MESSAGE, f"expected {_TYPES_LENGTH_MESSAGE!r}, got {message!r}"

    # Positive control: a single-element Types list is accepted and correctly scopes results.
    response = cc.list_controls(
        MaxResults=10, Filter={"Implementations": {"Types": ["AWS::Config::ConfigRule"]}}
    )
    controls = response.get("Controls", [])
    assert len(controls) > 0, "expected at least one AWS::Config::ConfigRule-implemented control"
    for c in controls:
        impl_type = c.get("Implementation", {}).get("Type")
        assert impl_type == "AWS::Config::ConfigRule", f"{c['Arn']}: Implementation.Type={impl_type}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
