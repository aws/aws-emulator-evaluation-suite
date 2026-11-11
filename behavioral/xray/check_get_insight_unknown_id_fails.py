"""get-insight-unknown-id-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-insight-unknown-id-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetInsight for a well-formed InsightId that was never generated is rejected with
    InvalidRequestException rather than returning an empty insight document. The id must satisfy
    InsightId's own pattern (UUID with the variant nibble in 8-b)."""
    xr = ctx.client("xray")
    code, message = _error(
        lambda: xr.get_insight(InsightId="11111111-2222-3333-8444-555555555555")
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert message == "Insight not found", f"unexpected message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
