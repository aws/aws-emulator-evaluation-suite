"""list-metric-streams-max-results-out-of-bounds-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-metric-streams-max-results-out-of-bounds-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListMetricStreams rejects MaxResults=501 and MaxResults=0 (outside [1, 500]) with ValidationError and
    the exact constraint message each, instead of clamping, while MaxResults=500 returns an Entries list;
    MaxResults=0 goes through a client with parameter validation off so the service, not the SDK, rejects it."""
    cw = ctx.client("cloudwatch")
    raw = ctx.client("cloudwatch", config=Config(parameter_validation=False))

    too_high_code, too_high_message = _error(lambda: cw.list_metric_streams(MaxResults=501))
    assert too_high_code == "ValidationError", (
        f"expected ValidationError for MaxResults=501, got {too_high_code!r}"
    )
    assert too_high_message == "1 validation error detected: Value '501' at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 500", f"unexpected message for MaxResults=501: {too_high_message!r}"

    too_low_code, too_low_message = _error(lambda: raw.list_metric_streams(MaxResults=0))
    assert too_low_code == "ValidationError", (
        f"expected ValidationError for MaxResults=0, got {too_low_code!r}"
    )
    assert too_low_message == "1 validation error detected: Value '0' at 'maxResults' failed to satisfy constraint: Member must have value greater than or equal to 1", f"unexpected message for MaxResults=0: {too_low_message!r}"

    # Positive control: the same call with an in-bounds (upper-boundary) value succeeds
    # and returns a well-formed page, not a clamped substitute for the rejected request.
    response = cw.list_metric_streams(MaxResults=500)
    assert "Entries" in response and isinstance(response["Entries"], list)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

