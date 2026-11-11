"""list-controls-max-results-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-controls-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["controlcatalog"]

_MAX_RESULTS_MESSAGE = (
    "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
    "Member must have value less than or equal to 100"
)


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListControls rejects a MaxResults value above the documented 1-100 range with
    ValidationException, while a MaxResults value at the upper bound still succeeds (in-file
    positive control)."""
    cc = ctx.client("controlcatalog")

    ok = cc.list_controls(MaxResults=100)
    assert len(ok["Controls"]) > 0, "positive control: MaxResults=100 (in-range) must return at least one control"

    code, message = _error_code(lambda: cc.list_controls(MaxResults=101))
    assert code == "ValidationException", f"expected ValidationException for MaxResults=101 (out of range), got {code!r}"
    assert message == _MAX_RESULTS_MESSAGE, f"expected {_MAX_RESULTS_MESSAGE!r}, got {message!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects MaxResults=101 as out of range, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
