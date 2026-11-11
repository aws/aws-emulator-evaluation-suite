"""list-controls-governed-provider-invalid-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-controls-governed-provider-invalid-pattern-rejected"
GROUP = "error-semantics"
SERVICES = ["controlcatalog"]

_GOVERNED_PROVIDER_MESSAGE = (
    "1 validation error detected: Value at 'filter.governedProviders' failed to satisfy constraint: "
    "Member must satisfy constraint: [Member must have length less than or equal to 64, "
    "Member must have length greater than or equal to 2, "
    "Member must satisfy regular expression pattern: [A-Z]{2,64}]"
)


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects GovernedProviders=['aws'], but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GovernedProviders filter values must match ^[A-Z]{2,64}$; a lowercase value is rejected."""
    cc = ctx.client("controlcatalog")

    code, message = _error_code(
        lambda: cc.list_controls(MaxResults=10, Filter={"GovernedProviders": ["aws"]})
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == _GOVERNED_PROVIDER_MESSAGE, f"expected {_GOVERNED_PROVIDER_MESSAGE!r}, got {message!r}"

    # Positive control: the same filter shape with a pattern-valid (uppercase) value succeeds.
    response = cc.list_controls(MaxResults=10, Filter={"GovernedProviders": ["AWS"]})
    assert "Controls" in response, f"expected a Controls field in the response, got {response!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
