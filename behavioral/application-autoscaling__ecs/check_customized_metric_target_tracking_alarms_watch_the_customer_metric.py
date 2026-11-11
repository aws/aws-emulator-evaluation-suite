"""customized-metric-target-tracking-alarms-watch-the-customer-metric."""
from __future__ import annotations


import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "customized-metric-target-tracking-alarms-watch-the-customer-metric"
GROUP = "scaling-policies"
SERVICES = ["application-autoscaling", "ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CustomizedMetricSpecification target-tracking policy round-trips the spec and mints exactly a
    high and a low CloudWatch alarm on the customer's own metric, the high one at the TargetValue:
    only CloudWatch shows which metric the scaling listens to.
    """
    aas = ctx.client("application-autoscaling")
    cw = ctx.client("cloudwatch")
    resource_id = _ecs_service(ctx)
    _register(ctx, aas, resource_id)
    policy = ctx.unique_name("sim2real-behav-aas-cm-")
    queue = ctx.unique_name("sim2real-behav-q-")
    spec = {"MetricName": "Backlog", "Namespace": "sim2real/behavioral",
            "Dimensions": [{"Name": "Queue", "Value": queue}], "Statistic": "Average", "Unit": "Count"}

    put = aas.put_scaling_policy(
        PolicyName=policy, ServiceNamespace="ecs", ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyType="TargetTrackingScaling",
        TargetTrackingScalingPolicyConfiguration={"TargetValue": 70.0, "CustomizedMetricSpecification": spec})
    names = [a["AlarmName"] for a in put["Alarms"]]
    assert len(names) == 2, f"a customized-metric policy minted {len(names)} alarms, expected 2"
    stored = _policies(aas, resource_id, [policy])[0]["TargetTrackingScalingPolicyConfiguration"]
    assert stored["CustomizedMetricSpecification"] == spec, (
        f"the customized metric spec read back as {stored['CustomizedMetricSpecification']!r}"
    )

    alarms = cw.describe_alarms(AlarmNames=names)["MetricAlarms"]
    assert len(alarms) == 2, f"{len(alarms)} of the 2 minted alarms are visible in CloudWatch"
    for a in alarms:
        watched = (a["Namespace"], a["MetricName"], a["Dimensions"], a["Statistic"], a.get("Unit"))
        assert watched == (spec["Namespace"], spec["MetricName"], spec["Dimensions"],
                           spec["Statistic"], spec["Unit"]), (
            f"alarm watches {watched[0]}/{watched[1]} dims={watched[2]!r} "
            f"stat={watched[3]!r} unit={watched[4]!r}, not the customer metric"
        )
        assert a["AlarmActions"] and a["AlarmActions"][0].startswith(put["PolicyARN"]), (
            "a minted alarm does not invoke the policy it was minted for"
        )
    by_op = {a["ComparisonOperator"]: a for a in alarms}
    assert set(by_op) == {"GreaterThanThreshold", "LessThanThreshold"}, (
        f"the two alarms compare with {sorted(by_op)!r}, expected one high and one low"
    )
    assert by_op["GreaterThanThreshold"]["Threshold"] == 70.0, (
        f"the high alarm fires above {by_op['GreaterThanThreshold']['Threshold']}, not the TargetValue 70.0"
    )
    assert by_op["LessThanThreshold"]["Threshold"] < 70.0, (
        f"the low alarm fires below {by_op['LessThanThreshold']['Threshold']}, not below the target"
    )


# ===== helpers =====
_DIM = "ecs:service:DesiredCount"


def _error(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _delete_cluster(ecs, cluster):
    """DeleteCluster fails while the force-deleted service is still draining; retry, then raise."""
    for _ in range(30):
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code != "ClusterContainsServicesException":
                raise
            time.sleep(5)
    ecs.delete_cluster(cluster=cluster)


def _delete_task_definition(ecs, arn):
    ecs.deregister_task_definition(taskDefinition=arn)
    ecs.delete_task_definitions(taskDefinitions=[arn])


def _ecs_service(ctx):
    """An idle EC2-launch-type service (desiredCount 0, no container instances) this check owns.

    Nothing runs and nothing bills: the service only gives Application Auto Scaling a real
    `service/<cluster>/<service>` resource to register."""
    ecs = ctx.client("ecs")
    cluster = ctx.unique_name("sim2real-behav-aas-")
    pairs = [{"key": "sim2real", "value": "behavioral"}]
    ecs.create_cluster(clusterName=cluster, tags=pairs)
    ctx.on_cleanup(lambda: _delete_cluster(ecs, cluster))
    task_def = ecs.register_task_definition(
        family=cluster, networkMode="bridge", requiresCompatibilities=["EC2"],
        containerDefinitions=[{"name": "sim2real-idle",
                               "image": "public.ecr.aws/docker/library/busybox:1.36",
                               "memory": 32, "essential": True}],
        tags=pairs,
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _delete_task_definition(ecs, task_def))
    service = "sim2real-svc"
    ecs.create_service(cluster=cluster, serviceName=service, taskDefinition=task_def,
                       desiredCount=0, launchType="EC2", tags=pairs)
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster, service=service, force=True))
    return f"service/{cluster}/{service}"


def _register(ctx, aas, resource_id, lo=0, hi=4):
    aas.register_scalable_target(ServiceNamespace="ecs", ResourceId=resource_id,
                                 ScalableDimension=_DIM, MinCapacity=lo, MaxCapacity=hi)

    def _deregister():
        try:
            aas.deregister_scalable_target(ServiceNamespace="ecs", ResourceId=resource_id,
                                           ScalableDimension=_DIM)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ObjectNotFoundException":
                raise
    ctx.on_cleanup(_deregister)


def _policies(aas, resource_id, names=None):
    kwargs = {"ServiceNamespace": "ecs", "ResourceId": resource_id, "ScalableDimension": _DIM}
    if names:
        kwargs["PolicyNames"] = names
    out = []
    for page in aas.get_paginator("describe_scaling_policies").paginate(**kwargs):
        out.extend(page["ScalingPolicies"])
    return out


_STEP = {
    "AdjustmentType": "ChangeInCapacity",
    "Cooldown": 45,
    "MetricAggregationType": "Maximum",
    "StepAdjustments": [
        {"MetricIntervalLowerBound": 0.0, "MetricIntervalUpperBound": 10.0, "ScalingAdjustment": 1},
        {"MetricIntervalLowerBound": 10.0, "ScalingAdjustment": 2},
    ],
}


def _put_step(aas, resource_id, name, config=None):
    return aas.put_scaling_policy(PolicyName=name, ServiceNamespace="ecs", ResourceId=resource_id,
                                  ScalableDimension=_DIM, PolicyType="StepScaling",
                                  StepScalingPolicyConfiguration=config or _STEP)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
