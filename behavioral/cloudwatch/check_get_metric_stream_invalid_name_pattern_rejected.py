"""get-metric-stream-invalid-name-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-metric-stream-invalid-name-pattern-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMetricStream rejects a Name outside the documented pattern (A-Z, a-z, 0-9, '-', '_') with
    InvalidParameterValue "Invalid Name", while a well-formed unknown name gets ResourceNotFoundException
    with an empty message, so the pattern violation is not treated as a plain not-found lookup."""
    cw = ctx.client("cloudwatch")

    # Positive control first: a real metric stream with a valid name can be
    # looked up (proves GetMetricStream/plain-not-found path both function).
    valid_name = ctx.unique_name("sim2real_mstream_pattern_")
    real_code, real_message = _error(lambda: cw.get_metric_stream(Name=valid_name))
    assert real_code == "ResourceNotFoundException", (
        f"expected a well-formed but nonexistent name to 404, got {real_code!r}"
    )
    # AWS returns this code with no message text.
    assert real_message == "", f"expected an empty message, got {real_message!r}"

    # Negative: a name containing characters outside the documented charset
    # (space and '!') must be rejected as a bad parameter, not treated the
    # same as the well-formed-but-missing case above.
    invalid_name = "sim2real bad name!"
    invalid_code, invalid_message = _error(lambda: cw.get_metric_stream(Name=invalid_name))
    assert invalid_code == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {invalid_code!r}"
    )
    assert invalid_message == "Invalid Name", f"expected the exact message 'Invalid Name', got {invalid_message!r}"
    assert invalid_code != real_code, "pattern violation must not collapse into plain not-found"


def _error(fn):
    """Call fn(); return its botocore error (code, message). A SUCCESS raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
