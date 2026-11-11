"""list-common-controls-max-results-upper-bound-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-common-controls-max-results-upper-bound-rejected"
GROUP = "overly-permissive"
SERVICES = ["controlcatalog"]

_MAX_RESULTS_MESSAGE = (
    "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
    "Member must have value less than or equal to 100"
)


def _error_code(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected ValidationException, but the call SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """MaxResults above the documented maximum of 100 is rejected, never silently clamped."""
    cc = ctx.client("controlcatalog")

    # Positive control: the boundary value 100 (the documented maximum) succeeds and returns
    # the non-empty, AWS-managed common-controls catalog.
    response = cc.list_common_controls(MaxResults=100)
    controls = response.get("CommonControls", [])
    assert controls, f"expected a non-empty common-controls catalog, got {controls!r}"
    assert len(controls) <= 100, f"expected at most 100 common controls, got {len(controls)}"

    code, message = _error_code(lambda: cc.list_common_controls(MaxResults=101))
    assert code == "ValidationException", f"expected ValidationException for MaxResults=101, got {code!r}"
    assert message == _MAX_RESULTS_MESSAGE, f"expected {_MAX_RESULTS_MESSAGE!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
