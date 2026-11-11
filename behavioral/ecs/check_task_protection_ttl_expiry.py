"""task-protection-ttl-expiry."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "task-protection-ttl-expiry"
GROUP = 'task-protection'
SERVICES = ['ecs']


_ECS_TAGS = [
    {"key": "sim2real:managed", "value": "true"},
    {"key": "sim2real:prefix", "value": "sim2real-behav"},
]


FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
    }
]


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(fn, pred, *, timeout_s, interval_s=5):
    deadline = time.monotonic() + timeout_s
    while True:
        val = fn()
        if pred(val):
            return val
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={val!r})")
        time.sleep(interval_s)


def _fargate_network(ctx):
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_UpdateTaskProtection.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """Task protection set with expiresInMinutes=1 on a service task reverts to
    protectionEnabled=False once the TTL elapses; an unknown cluster is rejected with
    InvalidParameterException and a standalone task via failures[]/TASK_NOT_VALID.
    """
    ecs = ctx.client("ecs")
    subnets, sg = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg], "assignPublicIp": "ENABLED"}
    }

    cluster = ecs.create_cluster(
        clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"), tags=_ECS_TAGS
    )["cluster"]
    name = cluster["clusterName"]

    def _teardown_cluster():
        # DeleteService and StopTask only start the async drain; DeleteCluster rejects with
        # ClusterContainsServicesException / ClusterContainsTasksException until the service
        # and the tasks have actually gone, so retry across the drain instead of firing once
        # and leaking the cluster.
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
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        tags=_ECS_TAGS,
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    svc_name = ctx.unique_name("svc-")
    ecs.create_service(
        cluster=name,
        serviceName=svc_name,
        taskDefinition=td_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
        tags=_ECS_TAGS,
    )
    def _teardown_service():
        try:
            ecs.update_service(cluster=name, service=svc_name, desiredCount=0)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ClusterNotFoundException",
                "NamespaceNotFoundException",
                "ServiceNotActiveException",
                "ServiceNotFoundException",
            ):
                raise
        ecs.delete_service(cluster=name, service=svc_name, force=True)

    ctx.on_cleanup(_teardown_service)

    def _running_service_task():
        arns = ecs.list_tasks(cluster=name, serviceName=svc_name).get("taskArns", [])
        if not arns:
            return None
        for t in ecs.describe_tasks(cluster=name, tasks=arns)["tasks"]:
            if t["lastStatus"] == "RUNNING":
                return t["taskArn"]
        return None

    task_arn = _poll_until(_running_service_task, lambda a: a is not None, timeout_s=180)

    # boundary #1: an unknown cluster is rejected outright.
    bogus_cluster = ctx.unique_name("no-such-cluster-")
    error = _error(
        lambda: ecs.update_task_protection(
            cluster=bogus_cluster, tasks=[task_arn], protectionEnabled=True
        )
    )
    expected = ("InvalidParameterException", "Invalid identifier: cluster identifiers mismatch")
    assert error == expected, f"expected {expected!r}, got {error!r}"

    # boundary #2: a standalone (non-service) task cannot be protected.
    standalone = ecs.run_task(
        cluster=name,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration=net_cfg,
    )
    assert not standalone.get("failures"), f"unexpected RunTask failures: {standalone.get('failures')}"
    standalone_arn = standalone["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=name, task=standalone_arn, reason="behavioral-cleanup"))
    standalone_task_id = standalone_arn.rsplit("/", 1)[-1]
    standalone_resp = ecs.update_task_protection(
        cluster=name, tasks=[standalone_arn], protectionEnabled=True
    )
    standalone_failures = {
        f.get("arn", "").rsplit("/", 1)[-1]: f.get("reason") for f in standalone_resp.get("failures", [])
    }
    assert standalone_failures.get(standalone_task_id) == "TASK_NOT_VALID", (
        f"expected TASK_NOT_VALID protecting a standalone task, got {standalone_resp}"
    )
    assert not any(
        p["taskArn"].rsplit("/", 1)[-1] == standalone_task_id
        for p in standalone_resp.get("protectedTasks", [])
    ), "a standalone task rejected via failures[] must not ALSO appear in protectedTasks[]"

    # --- the real TTL expiry state machine ---
    task_id = task_arn.rsplit("/", 1)[-1]
    before = time.time()
    enabled = ecs.update_task_protection(
        cluster=name, tasks=[task_arn], protectionEnabled=True, expiresInMinutes=1
    )
    assert not enabled.get("failures"), f"unexpected UpdateTaskProtection failures: {enabled}"
    protected = enabled["protectedTasks"][0]
    assert protected["taskArn"].rsplit("/", 1)[-1] == task_id, (
        f"expected protectedTasks[0] to identify task {task_id}, got {protected['taskArn']!r}"
    )
    assert protected["protectionEnabled"] is True, (
        f"expected protectionEnabled=True right after enabling it, got {protected['protectionEnabled']!r}"
    )
    expiration = protected.get("expirationDate")
    assert expiration is not None, "expected an expirationDate when a TTL is set"
    expiration_epoch = expiration.timestamp() if hasattr(expiration, "timestamp") else float(expiration)
    assert 0 < (expiration_epoch - before) <= 150, (
        f"expected a ~60s expiration window for expiresInMinutes=1, got {expiration_epoch - before}s"
    )

    got = ecs.get_task_protection(cluster=name, tasks=[task_arn])["protectedTasks"][0]
    assert got["protectionEnabled"] is True, f"expected GetTaskProtection to reflect enabled, got {got}"

    expired = _poll_until(
        lambda: ecs.get_task_protection(cluster=name, tasks=[task_arn])["protectedTasks"][0],
        lambda p: p["protectionEnabled"] is False,
        timeout_s=150,
    )
    assert expired["protectionEnabled"] is False, (
        f"expected protection to auto-expire to False after the TTL, got {expired}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
