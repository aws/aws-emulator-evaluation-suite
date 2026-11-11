"""step-scaling-policy-round-trips-and-lists-the-alarm-that-invokes-it."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "step-scaling-policy-round-trips-and-lists-the-alarm-that-invokes-it"
GROUP = "scaling-policies"
SERVICES = ["application-autoscaling", "ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A step policy mints no alarms, reads back its StepScalingPolicyConfiguration intact, and lists
    under Alarms exactly the customer CloudWatch alarm whose AlarmActions name its ARN.
    """
    aas = ctx.client("application-autoscaling")
    cw = ctx.client("cloudwatch")
    resource_id = _ecs_service(ctx)
    _register(ctx, aas, resource_id)
    policy = ctx.unique_name("sim2real-behav-aas-step-")

    put = _put_step(aas, resource_id, policy)
    assert put["Alarms"] == [], f"a step policy minted alarms of its own: {put['Alarms']!r}"
    stored = _policies(aas, resource_id, [policy])
    assert len(stored) == 1, f"expected one stored policy, got {len(stored)}"
    p = stored[0]
    assert (p["PolicyARN"], p["PolicyType"]) == (put["PolicyARN"], "StepScaling"), (
        f"stored policy read back as type {p['PolicyType']!r} with a different ARN"
    )
    assert p["StepScalingPolicyConfiguration"] == _STEP, (
        f"step configuration read back as {p['StepScalingPolicyConfiguration']!r}, sent {_STEP!r}"
    )
    assert p["Alarms"] == [], f"before any alarm points at it the policy lists {p['Alarms']!r}"

    alarm = ctx.unique_name("sim2real-behav-aas-al-")
    cw.put_metric_alarm(AlarmName=alarm, Namespace="sim2real/behavioral", MetricName="Backlog",
                        Statistic="Maximum", Period=60, EvaluationPeriods=1, Threshold=5.0,
                        ComparisonOperator="GreaterThanThreshold", AlarmActions=[put["PolicyARN"]])
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))

    listed = _poll_until(lambda: _policies(aas, resource_id, [policy])[0]["Alarms"], bool,
                         timeout_s=60, description="the customer alarm appearing under the policy")
    assert [a["AlarmName"] for a in listed] == [alarm], (
        f"the policy lists alarms {[a['AlarmName'] for a in listed]!r}, expected only the customer alarm"
    )
    assert listed[0]["AlarmARN"] == f"arn:aws:cloudwatch:{ctx.region}:{ctx.account}:alarm:{alarm}", (
        "the listed alarm ARN does not name the customer alarm in this account and region"
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
