"""task-role-credentials-endpoint-serves-task-role."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "task-role-credentials-endpoint-serves-task-role"
GROUP = 'task-execution'
SERVICES = ['ecs']

# ===== helpers =====


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


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With distinct taskRoleArn and executionRoleArn, the container-credentials endpoint serves
    the TASK role: the container exits 0 for the task role, 7 for the execution role, 8 for any
    other role and 9 when no credentials are served, and DescribeTasks reports that exit code.
    """
    ecs = ctx.client("ecs")
    iam = ctx.client("iam")

    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    task_role_name = ctx.unique_name("sim2real-behav-ecs-taskrole-")[:64]
    task_role_arn = iam.create_role(
        RoleName=task_role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=task_role_name))
    iam.put_role_policy(
        RoleName=task_role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "ecs:DescribeClusters", "Resource": "*"}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=task_role_name, PolicyName="inline"))

    exec_role_name = ctx.unique_name("sim2real-behav-ecs-execrole-")[:64]
    exec_role_arn = iam.create_role(
        RoleName=exec_role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_role_name))
    exec_policy = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=exec_role_name, PolicyArn=exec_policy)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=exec_role_name, PolicyArn=exec_policy)
    )
    assert task_role_name != exec_role_name, "the two roles must be distinguishable by name"

    cluster = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster))

    script = (
        'u="http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}"; '
        '[ -n "${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}" ] || exit 9; '
        'c=$(wget -q -O - "$u") || exit 9; '
        '[ -n "$c" ] || exit 9; '
        f'case "$c" in *{exec_role_name}*) exit 7;; esac; '
        f'case "$c" in *{task_role_name}*) exit 0;; *) exit 8;; esac'
    )
    td_arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-fg-"),
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", script],
            }
        ],
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        taskRoleArn=task_role_arn,
        executionRoleArn=exec_role_arn,
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    round_tripped = ecs.describe_task_definition(taskDefinition=td_arn)["taskDefinition"]
    assert round_tripped.get("taskRoleArn") == task_role_arn, (
        f"taskRoleArn must round-trip unchanged, got {round_tripped.get('taskRoleArn')!r}"
    )
    assert round_tripped.get("executionRoleArn") == exec_role_arn, (
        f"executionRoleArn must round-trip unchanged, got {round_tripped.get('executionRoleArn')!r}"
    )
    assert round_tripped["taskRoleArn"] != round_tripped["executionRoleArn"], (
        "the two role fields must remain independent, not collapsed onto one value"
    )

    subnets, sg = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": subnets[:1],
            "securityGroups": [sg],
            "assignPublicIp": "ENABLED",
        }
    }

    # The roles were just created; ECS's own PassRole/AssumeRole check against a
    # brand-new trust policy can lag, so retry RunTask itself rather than sleeping.
    def _attempt():
        try:
            return ecs.run_task(
                cluster=cluster,
                taskDefinition=td_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration=net_cfg,
            )
        except ClientError as exc:
            return exc

    resp = _poll_until(
        _attempt,
        lambda r: not isinstance(r, ClientError),
        timeout_s=180,
        interval_s=10,
        description="the freshly created roles propagate enough for ECS to assume them",
    )
    assert not resp.get("failures"), f"unexpected RunTask failures: {resp.get('failures')}"
    task_arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: ecs.stop_task(cluster=cluster, task=task_arn, reason="behavioral-cleanup")
    )

    stopped = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0],
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=600,
        interval_s=10,
        description="the credential-probing task runs to completion",
    )
    container = next(c for c in stopped.get("containers", []) if c["name"] == "app")
    exit_code = container.get("exitCode")
    diagnostics = {
        9: "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI was unset or 169.254.170.2 served nothing "
           "— there is no task credential plane",
        8: "the credential endpoint served credentials that are NOT the task role",
        7: "the credential endpoint served the EXECUTION role instead of the TASK role",
    }
    assert exit_code == 0, (
        "the container-credentials endpoint must serve the TASK role: "
        f"{diagnostics.get(exit_code, 'unexpected exit code')} "
        f"(exitCode={exit_code!r}, reason={container.get('reason')!r}, "
        f"stopCode={stopped.get('stopCode')!r}, stoppedReason={stopped.get('stoppedReason')!r})"
    )
    assert stopped.get("stopCode") == "EssentialContainerExited", (
        f"the task must have stopped because its probe container exited, got {stopped.get('stopCode')!r}"
    )


def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services, tasks or container instances remain, and a task's
    ENI stays in the shared network until the task has stopped, which keeps the network from
    being deleted.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s

    def arns(op, key, **kw):
        return [a for page in ecs.get_paginator(op).paginate(cluster=cluster, **kw) for a in page.get(key, [])]

    try:
        services = arns("list_services", "serviceArns")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for service in services:
        for call in (
            lambda s=service: ecs.update_service(cluster=cluster, service=s, desiredCount=0),
            lambda s=service: ecs.delete_service(cluster=cluster, service=s, force=True),
        ):
            try:
                call()
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("ServiceNotFoundException", "ServiceNotActiveException"):
                    raise
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                    raise
        stopping = arns("list_tasks", "taskArns", desiredStatus="STOPPED")
        live = []
        for i in range(0, len(stopping), 100):
            live += [t for t in ecs.describe_tasks(cluster=cluster, tasks=stopping[i:i + 100])["tasks"]
                     if t.get("lastStatus") != "STOPPED"]
        if not live and not arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still not STOPPED after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code == "ClusterContainsContainerInstancesException":
                for instance in arns("list_container_instances", "containerInstanceArns"):
                    try:
                        ecs.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                            raise
            elif code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
                "ResourceInUseException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
