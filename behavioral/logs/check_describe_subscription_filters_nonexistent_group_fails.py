"""describe-subscription-filters-nonexistent-group-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _expect_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")

CHECK = "describe-subscription-filters-nonexistent-group-fails"
GROUP = 'subscription-filters'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: DescribeSubscriptionFilters on a nonexistent log group must fail.

    Note: real AWS is lenient on PutSubscriptionFilter for a missing log group,
    but the read path does enforce existence.
    """
    svc = ctx.client("logs")

    # Positive control: the SAME call succeeds against a real log group, so the
    # negative below cannot be satisfied by a target that rejects every
    # DescribeSubscriptionFilters call regardless of input.
    real_group = ctx.unique_name("sim2real-behav-lg-sub-real-")
    svc.create_log_group(logGroupName=real_group)
    ctx.on_cleanup(lambda: svc.delete_log_group(logGroupName=real_group))
    filters = svc.describe_subscription_filters(logGroupName=real_group).get("subscriptionFilters")
    assert filters == [], f"expected no subscription filters on a fresh log group, got {filters}"

    missing_group = ctx.unique_name("sim2real-behav-lg-sub-missing-")
    code, message = _expect_error(lambda: svc.describe_subscription_filters(logGroupName=missing_group))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "The specified log group does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
