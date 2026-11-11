"""describe-insights-refresh-unknown-cluster-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-insights-refresh-unknown-cluster-not-found"
GROUP = "error-semantics"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeInsightsRefresh against a nonexistent cluster returns
    ResourceNotFoundException rather than succeeding or a different error class."""
    eks = ctx.client("eks")
    fake_cluster = ctx.unique_name("sim2real-eks-nonexistent-")

    code, msg = _error_code(lambda: eks.describe_insights_refresh(clusterName=fake_cluster))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"No cluster found for name: {fake_cluster}."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"


def _error_code(fn):
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"describe_insights_refresh on an unknown cluster SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
