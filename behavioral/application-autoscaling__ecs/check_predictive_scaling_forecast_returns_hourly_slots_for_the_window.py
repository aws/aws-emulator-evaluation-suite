"""predictive-scaling-forecast-returns-hourly-slots-for-the-window."""
from __future__ import annotations

import datetime as dt
import math
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "predictive-scaling-forecast-returns-hourly-slots-for-the-window"
GROUP = "scaling-policies"
SERVICES = ["application-autoscaling", "ecs"]

_SPEC = {"TargetValue": 40.0,
         "PredefinedMetricPairSpecification": {"PredefinedMetricType": "ECSServiceCPUUtilization"}}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ForecastOnly predictive policy reads back as stored and mints no alarms; its 24 h forecast
    has load and capacity series on the same hourly slots inside the window, all NaN with no
    history.
    """
    aas = ctx.client("application-autoscaling")
    resource_id = _ecs_service(ctx)
    _register(ctx, aas, resource_id)
    policy = ctx.unique_name("sim2real-behav-aas-pred-")
    put = aas.put_scaling_policy(
        PolicyName=policy, ServiceNamespace="ecs", ResourceId=resource_id, ScalableDimension=_DIM,
        PolicyType="PredictiveScaling",
        PredictiveScalingPolicyConfiguration={"MetricSpecifications": [_SPEC], "Mode": "ForecastOnly"})
    assert put["Alarms"] == [], f"a predictive policy minted alarms: {put['Alarms']!r}"
    stored = _policies(aas, resource_id, [policy])
    assert len(stored) == 1 and stored[0]["PolicyType"] == "PredictiveScaling", (
        f"stored policy read back as {[(p['PolicyName'], p['PolicyType']) for p in stored]!r}"
    )
    cfg = stored[0]["PredictiveScalingPolicyConfiguration"]
    assert (cfg["MetricSpecifications"], cfg["Mode"]) == ([_SPEC], "ForecastOnly"), (
        f"predictive configuration read back as {cfg!r}"
    )

    start = dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0, microsecond=0)
    end = start + dt.timedelta(hours=24)
    fc = aas.get_predictive_scaling_forecast(
        ServiceNamespace="ecs", ResourceId=resource_id, ScalableDimension=_DIM, PolicyName=policy,
        StartTime=start, EndTime=end)
    loads = fc["LoadForecast"]
    assert len(loads) == 1, f"expected one load forecast for one metric specification, got {len(loads)}"
    load = loads[0]
    assert load["MetricSpecification"] == _SPEC, (
        f"load forecast names metric specification {load['MetricSpecification']!r}"
    )
    stamps = load["Timestamps"]
    assert stamps, "the load forecast has no timestamps"
    assert len(load["Values"]) == len(stamps), (
        f"{len(load['Values'])} load values for {len(stamps)} timestamps"
    )
    for earlier, later in zip(stamps, stamps[1:]):
        assert later - earlier == dt.timedelta(hours=1), f"forecast slots are not hourly: {earlier} -> {later}"
    assert all(t.minute == t.second == 0 for t in stamps), "forecast slots are not hour-aligned"
    assert start <= stamps[0] and stamps[-1] < end, (
        f"forecast slots run {stamps[0]} .. {stamps[-1]}, outside the window [{start}, {end})"
    )
    assert stamps[-1] == end - dt.timedelta(hours=1), (
        f"the last slot is {stamps[-1]}; the window's last hour before {end} must be forecast"
    )
    cap = fc["CapacityForecast"]
    assert cap["Timestamps"] == stamps, "the capacity forecast is not on the load forecast's timestamps"
    assert len(cap["Values"]) == len(stamps), f"{len(cap['Values'])} capacity values for {len(stamps)} slots"
    assert all(math.isnan(float(v)) for v in load["Values"] + cap["Values"]), (
        "a service with no load history produced a numeric forecast"
    )


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
