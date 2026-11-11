"""task-protection-expires-range-validation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "task-protection-expires-range-validation"
GROUP = 'overly-permissive'
SERVICES = ['ecs']


FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
    }
]


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateTaskProtection rejects an expiresInMinutes outside [1, 2880] on a running service
    task with InvalidParameterException, leaving the prior in-range window untouched; an
    in-range positive control proves the rejection is specific to the value.
    """
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name)

    def _teardown_cluster():
        # DeleteService only starts the async drain; DeleteCluster rejects with
        # ClusterContainsServicesException / ClusterContainsTasksException until the service
        # and its tasks have gone, so retry across the drain within a bound.
        deadline = time.monotonic() + 240
        while True:
            try:
                ecs.delete_cluster(cluster=name)
                return
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ClusterNotFoundException":
                    return
                if code not in (
                    "ClusterContainsServicesException",
                    "ClusterContainsTasksException",
                ) or time.monotonic() >= deadline:
                    raise
                time.sleep(5)

    ctx.on_cleanup(_teardown_cluster)
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"]))
    subnets, sg = _fargate_network(ctx)

    svc_name = ctx.unique_name("sim2real-behav-ecs-svc-")
    ecs.create_service(
        cluster=name,
        serviceName=svc_name,
        taskDefinition=td["taskDefinitionArn"],
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets[:1],
                "securityGroups": [sg],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=name, service=svc_name, force=True))

    def _running_service_task():
        arns = ecs.list_tasks(cluster=name, serviceName=svc_name).get("taskArns", [])
        if not arns:
            return None
        tasks = ecs.describe_tasks(cluster=name, tasks=arns)["tasks"]
        for t in tasks:
            if t["lastStatus"] == "RUNNING":
                return t["taskArn"]
        return None

    task_arn = _poll_until(
        _running_service_task,
        lambda a: a is not None,
        timeout_s=180,
        interval_s=5,
        description="the service's task reaches RUNNING",
    )

    # Positive control: an in-range expiresInMinutes must be accepted and take effect, so a
    # later rejection can be attributed to the specific out-of-range value rather than to the
    # target refusing UpdateTaskProtection outright.
    control = ecs.update_task_protection(
        cluster=name, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=10
    )
    # A protected task survives DeleteService's scale-in, so release the protection first.
    ctx.on_cleanup(
        lambda: ecs.update_task_protection(cluster=name, tasks=[task_arn], protectionEnabled=False)
    )
    assert not control.get("failures"), (
        f"positive-control UpdateTaskProtection (expiresInMinutes=10) failed: {control['failures']}"
    )
    controlled = control["protectedTasks"][0]
    assert controlled["protectionEnabled"] is True, (
        f"positive control (expiresInMinutes=10) must enable protection, got {controlled}"
    )

    # overly-permissive boundary: expiresInMinutes outside the documented [1, 2880] range.
    for bad_value, message in (
        (0, "expiresInMinutes must be at least 1"),
        (5000, "expiresInMinutes must be at most 2880"),
    ):
        error = _error(
            lambda v=bad_value: ecs.update_task_protection(
                cluster=name, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=v
            )
        )
        expected = ("InvalidParameterException", message)
        assert error == expected, (
            f"expected {expected!r} for expiresInMinutes={bad_value} (outside [1, 2880]), got {error!r}"
        )

    unaffected = ecs.get_task_protection(cluster=name, tasks=[task_arn])["protectedTasks"][0]
    assert unaffected["protectionEnabled"] is True, (
        f"rejected out-of-range UpdateTaskProtection calls must not disturb the existing "
        f"protection state established by the positive control, got {unaffected}"
    )
    expiration_drift_s = abs(
        (unaffected["expirationDate"] - controlled["expirationDate"]).total_seconds()
    )
    assert expiration_drift_s < 1, (
        f"rejected out-of-range UpdateTaskProtection calls must not change the existing "
        f"expiration, expected ~{controlled['expirationDate']}, got {unaffected['expirationDate']} "
        f"(drift {expiration_drift_s}s)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
