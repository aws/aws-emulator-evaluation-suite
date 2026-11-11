"""delete-metric-stream-missing-required-parameter-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-metric-stream-missing-required-parameter-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteMetricStream with no Name, sent past client-side validation, fails with ValidationError
    "1 validation error detected: Value null at 'name' failed to satisfy constraint: Member must not
    be null"; a well-formed Name, even of a stream that never existed, succeeds."""
    cw = ctx.client("cloudwatch")
    probe = ctx.client("cloudwatch", config=Config(parameter_validation=False))

    # Positive control: the account, credentials and service are otherwise healthy
    # for this exact operation. DeleteMetricStream accepts any syntactically valid
    # Name -- even one naming a stream that has never existed -- as a permissive
    # no-op, so this must succeed.
    bogus_name = ctx.unique_name("sim2real-behav-ms-missing-")
    _must_succeed(
        lambda: cw.delete_metric_stream(Name=bogus_name),
        what="DeleteMetricStream for a syntactically valid but nonexistent Name (positive control)",
    )

    # Break exactly one thing: an otherwise well-formed request with no Name at all.
    code, message = _error_or_raise(lambda: probe.delete_metric_stream(), what="a Name-less DeleteMetricStream")
    assert code == "ValidationError", (
        f"expected ValidationError for a Name-less DeleteMetricStream, got {code!r}"
    )
    expected_message = "1 validation error detected: Value null at 'name' failed to satisfy constraint: Member must not be null"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _must_succeed(fn, *, what):
    """Call fn(); raise if it was rejected, so a rejected control fails here rather than
    surfacing as a false negative elsewhere in the check."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        raise AssertionError(f"expected {what} to succeed, but it was rejected with {code!r}") from exc


def _error_or_raise(fn, *, what):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, so an
    over-permissive target accepting input AWS refuses is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected {what} to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
