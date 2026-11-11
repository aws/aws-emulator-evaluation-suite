"""list-metric-streams-invalid-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-metric-streams-invalid-next-token-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListMetricStreams called with a malformed pagination token raises InvalidNextToken
    instead of silently starting over from the first page."""
    cw = ctx.client("cloudwatch")

    # Positive control: the same call shape with no token must succeed. Without this, a
    # rejection below cannot be attributed to the garbled token specifically -- it would be
    # indistinguishable from an account/region that can never call ListMetricStreams at all.
    control = cw.list_metric_streams()
    assert "Entries" in control, f"ListMetricStreams with no token did not succeed: {control!r}"

    code, message = _error(
        lambda: cw.list_metric_streams(NextToken="not-a-real-token-garbled==///")
    )
    assert code == "InvalidNextToken", code
    assert message == 'Invalid NextToken', f"unexpected InvalidNextToken message: {message!r}"


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
