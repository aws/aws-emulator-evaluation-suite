"""op-contract-describe-spot-price-history."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "op-contract-describe-spot-price-history"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSpotPriceHistory: real historical price data round-trips for a common
    instance type; DryRun is the distinct error boundary."""
    ec2 = ctx.client("ec2")
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=7)

    resp = ec2.describe_spot_price_history(
        StartTime=start,
        EndTime=end,
        InstanceTypes=["t3.micro"],
        ProductDescriptions=["Linux/UNIX"],
        MaxResults=50,
    )
    history = resp.get("SpotPriceHistory", [])
    if not history:
        raise AssertionError(
            "no spot price history returned for t3.micro/Linux-UNIX in the last 7 days"
        )
    entry = history[0]
    assert entry["InstanceType"] == "t3.micro", (
        f"expected InstanceType 't3.micro', got {entry.get('InstanceType')!r}"
    )
    assert float(entry["SpotPrice"]) > 0, (
        f"expected a positive SpotPrice, got {entry.get('SpotPrice')!r}"
    )

    # Error boundary: DryRun.
    code, code_message = _error_code(lambda: ec2.describe_spot_price_history(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    expected_code_message = "Request would have succeeded, but DryRun flag is set."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
