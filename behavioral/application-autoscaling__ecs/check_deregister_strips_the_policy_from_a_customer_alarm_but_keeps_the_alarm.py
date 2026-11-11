"""deregister-strips-the-policy-from-a-customer-alarm-but-keeps-the-alarm."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-strips-the-policy-from-a-customer-alarm-but-keeps-the-alarm"
GROUP = "scalable-targets"
SERVICES = ["application-autoscaling", "ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Deregistering a scalable target deletes its step policy and removes that policy's ARN from the
    customer's own CloudWatch alarm's AlarmActions, leaving the alarm and its settings in place.
    """
    aas = ctx.client("application-autoscaling")
    cw = ctx.client("cloudwatch")
    resource_id = _ecs_service(ctx)
    _register(ctx, aas, resource_id)
    policy = ctx.unique_name("sim2real-behav-aas-step-")
    policy_arn = _put_step(aas, resource_id, policy)["PolicyARN"]

    alarm = ctx.unique_name("sim2real-behav-aas-al-")
    cw.put_metric_alarm(AlarmName=alarm, Namespace="sim2real/behavioral", MetricName="Backlog",
                        Statistic="Maximum", Period=60, EvaluationPeriods=1, Threshold=5.0,
                        ComparisonOperator="GreaterThanThreshold", AlarmActions=[policy_arn])
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))
    before = cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"]
    assert len(before) == 1 and before[0]["AlarmActions"] == [policy_arn], (
        f"the customer alarm does not hold the policy as its only action: {before!r}"
    )

    aas.deregister_scalable_target(ServiceNamespace="ecs", ResourceId=resource_id,
                                   ScalableDimension=_DIM)
    assert _policies(aas, resource_id) == [], "the step policy outlived its deregistered target"

    after = _poll_until(lambda: cw.describe_alarms(AlarmNames=[alarm])["MetricAlarms"],
                        lambda a: not a or a[0]["AlarmActions"] != [policy_arn], timeout_s=120,
                        interval_s=5.0, description="the policy ARN leaving the customer alarm")
    assert len(after) == 1, "deregistering the target deleted the customer's own alarm"
    a = after[0]
    assert a["AlarmActions"] == [], f"the customer alarm's AlarmActions became {a['AlarmActions']!r}"
    assert (a["Namespace"], a["MetricName"], a["Threshold"], a["ComparisonOperator"]) == (
        "sim2real/behavioral", "Backlog", 5.0, "GreaterThanThreshold"), (
        f"the customer alarm's definition changed to {a['Namespace']}/{a['MetricName']} "
        f"{a['ComparisonOperator']} {a['Threshold']}"
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
