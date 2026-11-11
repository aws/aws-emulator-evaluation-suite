"""describe-auto-scaling-groups-invalid-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-auto-scaling-groups-invalid-next-token-rejected"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAutoScalingGroups with a bogus NextToken is rejected with InvalidNextToken, while
    the same call without a token succeeds, so the rejection is specific to the malformed token."""
    autoscaling = ctx.client("autoscaling")

    bogus_token = "sim2real-not-a-real-continuation-token=="
    error = _error(lambda: autoscaling.describe_auto_scaling_groups(NextToken=bogus_token))
    code = error.get("Code")
    assert code == "InvalidNextToken", f"expected InvalidNextToken, got {code}"
    expected_message = f"The token '{bogus_token}' was invalid"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    resp = autoscaling.describe_auto_scaling_groups(MaxRecords=1)
    assert "AutoScalingGroups" in resp


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
