"""op-contract-disable-aws-network-performance-metric-subscription."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-aws-network-performance-metric-subscription"
GROUP = "error-semantics"
SERVICES = ["ec2"]

# Source/Destination are the operation's own subject under test (an arbitrary monitored
# region pair), not the ambient deployment region ctx.region names the API endpoint (us-west-2).
_SOURCE = "us-east-1"
_DESTINATION = "us-west-2"
_METRIC = "aggregate-latency"
_STATISTIC = "p50"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-network-performance-subscription")
def run(ctx) -> None:
    """DisableAwsNetworkPerformanceMetricSubscription with DryRun answers DryRunOperation and the enabled
    subscription stays listed; the real call reports Output true and the subscription no longer
    describes."""
    ec2 = ctx.client("ec2")

    def _is_present() -> bool:
        subs = ec2.describe_aws_network_performance_metric_subscriptions()["Subscriptions"]
        return any(
            sub.get("Source") == _SOURCE
            and sub.get("Destination") == _DESTINATION
            and sub.get("Metric") == _METRIC
            and sub.get("Statistic") == _STATISTIC
            for sub in subs
        )

    def _cleanup():
        ec2.disable_aws_network_performance_metric_subscription(
            Source=_SOURCE, Destination=_DESTINATION, Metric=_METRIC, Statistic=_STATISTIC
        )

    ctx.on_cleanup(_cleanup)

    # POSITIVE CONTROL: enable, then an independent read confirms the pair is now tracked.
    enable_resp = ec2.enable_aws_network_performance_metric_subscription(
        Source=_SOURCE, Destination=_DESTINATION, Metric=_METRIC, Statistic=_STATISTIC
    )
    assert enable_resp["Output"] is True, f"enable did not report success: {enable_resp}"
    assert _is_present() is True, "subscription did not appear via Describe after enable"

    # NEGATIVE: DryRun must reject with the specific code and must not disable it.
    code, message = _error(lambda: ec2.disable_aws_network_performance_metric_subscription(
        Source=_SOURCE, Destination=_DESTINATION, Metric=_METRIC, Statistic=_STATISTIC, DryRun=True
    ))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )
    assert _is_present() is True, "DryRun must not disable the subscription, but it is now absent"

    # RESTORE / POSITIVE: the identical call without DryRun disables it for real, and an
    # independent read at the terminal is the proof, not the mutating call's own response.
    disable_resp = ec2.disable_aws_network_performance_metric_subscription(
        Source=_SOURCE, Destination=_DESTINATION, Metric=_METRIC, Statistic=_STATISTIC
    )
    assert disable_resp["Output"] is True, f"disable did not report success: {disable_resp}"
    assert _is_present() is False, "subscription still present via Describe after disable"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
