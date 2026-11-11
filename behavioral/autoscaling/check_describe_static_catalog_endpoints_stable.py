"""describe-static-catalog-endpoints-stable."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-static-catalog-endpoints-stable"
GROUP = "server-side"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The Describe*Types catalog operations (adjustment, notification, metric collection, scaling
    process, termination policy, lifecycle hook) return fixed AWS enumerations: they contain the
    well-known values and are identical across repeated calls."""
    asg = ctx.client("autoscaling")

    adjustment_1 = {a["AdjustmentType"] for a in asg.describe_adjustment_types()["AdjustmentTypes"]}
    adjustment_2 = {a["AdjustmentType"] for a in asg.describe_adjustment_types()["AdjustmentTypes"]}
    assert adjustment_1 == adjustment_2, (
        f"AdjustmentTypes changed across repeated calls: {adjustment_1} vs {adjustment_2}"
    )
    assert adjustment_1 == {"ChangeInCapacity", "ExactCapacity", "PercentChangeInCapacity"}, (
        f"unexpected AdjustmentTypes set: {adjustment_1}"
    )

    notif_1 = set(asg.describe_auto_scaling_notification_types()["AutoScalingNotificationTypes"])
    notif_2 = set(asg.describe_auto_scaling_notification_types()["AutoScalingNotificationTypes"])
    assert notif_1 == notif_2, (
        f"AutoScalingNotificationTypes changed across repeated calls: {notif_1} vs {notif_2}"
    )
    required_notifications = {
        "autoscaling:EC2_INSTANCE_LAUNCH",
        "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
        "autoscaling:EC2_INSTANCE_TERMINATE",
        "autoscaling:EC2_INSTANCE_TERMINATE_ERROR",
        "autoscaling:TEST_NOTIFICATION",
    }
    assert required_notifications.issubset(notif_1), (
        f"missing well-known notification types: {required_notifications - notif_1}"
    )

    metrics_resp_1 = asg.describe_metric_collection_types()
    metrics_resp_2 = asg.describe_metric_collection_types()
    granularities_1 = {g["Granularity"] for g in metrics_resp_1["Granularities"]}
    metric_names_1 = {m["Metric"] for m in metrics_resp_1["Metrics"]}
    metric_names_2 = {m["Metric"] for m in metrics_resp_2["Metrics"]}
    assert granularities_1 == {"1Minute"}, f"unexpected Granularities: {granularities_1}"
    assert metric_names_1 == metric_names_2, (
        f"Metrics list changed across repeated calls: {metric_names_1} vs {metric_names_2}"
    )
    expected_metrics = {
        "GroupMinSize",
        "GroupMaxSize",
        "GroupDesiredCapacity",
        "GroupInServiceInstances",
        "GroupPendingInstances",
        "GroupTerminatingInstances",
        "GroupTerminatingRetainedInstances",
        "GroupStandbyInstances",
        "GroupTotalInstances",
        "GroupInServiceCapacity",
        "GroupPendingCapacity",
        "GroupStandbyCapacity",
        "GroupTerminatingCapacity",
        "GroupTerminatingRetainedCapacity",
        "GroupTotalCapacity",
        "WarmPoolMinSize",
        "WarmPoolDesiredCapacity",
        "WarmPoolWarmedCapacity",
        "WarmPoolPendingCapacity",
        "WarmPoolPendingRetainedCapacity",
        "WarmPoolTerminatingCapacity",
        "WarmPoolTerminatingRetainedCapacity",
        "WarmPoolTotalCapacity",
        "GroupAndWarmPoolDesiredCapacity",
        "GroupAndWarmPoolTotalCapacity",
    }
    assert metric_names_1 >= expected_metrics, (
        f"missing metric collection types {expected_metrics - metric_names_1} in {metric_names_1}"
    )

    processes_1 = {p["ProcessName"] for p in asg.describe_scaling_process_types()["Processes"]}
    processes_2 = {p["ProcessName"] for p in asg.describe_scaling_process_types()["Processes"]}
    assert processes_1 == processes_2, (
        f"ScalingProcessTypes changed across repeated calls: {processes_1} vs {processes_2}"
    )
    expected_processes = {
        "Launch",
        "Terminate",
        "AddToLoadBalancer",
        "AlarmNotification",
        "AZRebalance",
        "HealthCheck",
        "InstanceRefresh",
        "ReplaceUnhealthy",
        "ScheduledActions",
    }
    assert expected_processes == processes_1, f"unexpected ScalingProcessTypes set: {processes_1}"

    termination_1 = set(asg.describe_termination_policy_types()["TerminationPolicyTypes"])
    termination_2 = set(asg.describe_termination_policy_types()["TerminationPolicyTypes"])
    assert termination_1 == termination_2, (
        f"TerminationPolicyTypes changed across repeated calls: {termination_1} vs {termination_2}"
    )
    expected_termination = {
        "OldestInstance",
        "NewestInstance",
        "OldestLaunchConfiguration",
        "ClosestToNextInstanceHour",
        "Default",
        "OldestLaunchTemplate",
        "AllocationStrategy",
        "Lambda",
    }
    assert termination_1 >= expected_termination, (
        f"missing TerminationPolicyTypes {expected_termination - termination_1} in {termination_1}"
    )

    hooks_1 = set(asg.describe_lifecycle_hook_types()["LifecycleHookTypes"])
    hooks_2 = set(asg.describe_lifecycle_hook_types()["LifecycleHookTypes"])
    assert hooks_1 == hooks_2, f"LifecycleHookTypes changed across repeated calls: {hooks_1} vs {hooks_2}"
    assert hooks_1 == {"autoscaling:EC2_INSTANCE_LAUNCHING", "autoscaling:EC2_INSTANCE_TERMINATING"}, (
        f"unexpected LifecycleHookTypes set: {hooks_1}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
