"""start-metric-streams-missing-required-parameter-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-metric-streams-missing-required-parameter-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartMetricStreams with Names absent from the request (client-side validation off) fails
    with ValidationError and the exact null-'names' message, while Names=[] is accepted, so the
    refusal is the service's own."""
    cw = ctx.client("cloudwatch")
    novalidate_cw = ctx.client("cloudwatch", config=Config(parameter_validation=False))

    try:
        cw.start_metric_streams(Names=[])
    except ClientError as exc:
        raise AssertionError(
            "positive control failed: StartMetricStreams(Names=[]) was unexpectedly "
            f"rejected with {exc.response['Error']['Code']!r}"
        ) from exc

    error = _client_error(lambda: novalidate_cw.start_metric_streams())
    # Measured against real AWS, not guessed: unlike CloudWatch's classic-Query-protocol
    # operations (which answer a dropped required field with the generic "MissingParameter"
    # common error), StartMetricStreams answers with its own modelled validation error.
    assert error.get("Code") == "ValidationError", (
        f"expected ValidationError for Names dropped entirely from the wire, got {error!r}"
    )
    assert error.get("Message") == (
        "1 validation error detected: Value null at 'names' failed to satisfy constraint: "
        "Member must not be null"
    ), (
        f"expected the message to name the null 'names' member, got {error.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a rejection but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
