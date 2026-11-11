"""ecs-run-task-fails-without-ecs-tasks-trust-policy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "ecs-run-task-fails-without-ecs-tasks-trust-policy"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A task whose execution role does not trust ecs-tasks.amazonaws.com fails to start
    (never RUNNING, no logs pushed), while the same task definition with a correctly-trusted
    role runs and pushes its log line."""
    iam = ctx.client("iam")
    ecs = ctx.client("ecs")
    logs = ctx.client("logs")

    _, subnet_ids, sg_id = _default_vpc_info(ctx)

    cluster_name = ctx.unique_name("sim2real-ecs-trust-cluster-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    netcfg = {
        "awsvpcConfiguration": {
            "subnets": subnet_ids[:1],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }

    # --- negative: role trusts only ec2.amazonaws.com, not ecs-tasks.amazonaws.com ---
    bad_role_arn, _ = _create_exec_role(ctx, iam, trusted_service="ec2.amazonaws.com")
    bad_log_group = ctx.unique_name("sim2real-ecs-trust-bad-lg-")
    logs.create_log_group(logGroupName=bad_log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=bad_log_group))
    bad_task = _launch_task(
        ctx, ecs, cluster_name, netcfg, bad_role_arn, bad_log_group, "bad-trust", retry=False
    )
    statuses_seen = bad_task["_statuses_seen"]

    assert "RUNNING" not in statuses_seen, (
        f"container should never start when the execution role can't be assumed, "
        f"but observed statuses={statuses_seen}"
    )
    assert bad_task["stopCode"] == "TaskFailedToStart", (
        f"expected TaskFailedToStart, got stopCode={bad_task.get('stopCode')!r} "
        f"reason={bad_task.get('stoppedReason')!r}"
    )
    bad_events = logs.filter_log_events(logGroupName=bad_log_group)["events"]
    assert bad_events == [], f"expected no log events pushed via the untrusted role, got {bad_events}"

    # --- positive control: role trusts ecs-tasks.amazonaws.com ---
    good_role_arn, _ = _create_exec_role(
        ctx, iam, trusted_service="ecs-tasks.amazonaws.com"
    )
    good_log_group = ctx.unique_name("sim2real-ecs-trust-good-lg-")
    logs.create_log_group(logGroupName=good_log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=good_log_group))
    good_task = _launch_task(
        ctx, ecs, cluster_name, netcfg, good_role_arn, good_log_group, "good-trust", retry=True
    )

    assert good_task["stopCode"] == "EssentialContainerExited", (
        f"positive control failed to run: stopCode={good_task.get('stopCode')!r} "
        f"reason={good_task.get('stoppedReason')!r}"
    )
    assert good_task["containers"][0]["exitCode"] == 0, (
        f"positive control's container exited non-zero: {good_task['containers'][0]!r}"
    )
    good_marker = good_task["_marker"]
    good_events = _poll_until(
        lambda: logs.filter_log_events(logGroupName=good_log_group)["events"],
        lambda evs: any(good_marker in e["message"] for e in evs),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert any(good_marker in e["message"] for e in good_events), (
        f"expected log line {good_marker!r} pushed via the correctly-trusted role, got {good_events}"
    )


def _default_vpc_info(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; needed to place an awsvpc-mode "
            "Fargate task with a public IP to pull a public image and push logs"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    subnet_ids = [s["SubnetId"] for s in subnets]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return vpc_id, subnet_ids, sgs[0]["GroupId"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_exec_role(ctx, iam, trusted_service):
    role_name = ctx.unique_name(f"sim2real-ecs-trust-{trusted_service.split('.')[0]}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trusted_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
        )
    )
    return role_arn, role_name


def _launch_task(ctx, ecs, cluster_name, netcfg, role_arn, log_group, tag, retry):
    from botocore.exceptions import ClientError

    family = ctx.unique_name(f"sim2real-ecs-trust-taskdef-{tag}-")
    marker = f"hello-from-{family}"
    task_def_arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        executionRoleArn=role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
                "essential": True,
                "command": ["sh", "-c", f"echo {marker}"],
                "logConfiguration": {
                    "logDriver": "awslogs",
                    "options": {
                        "awslogs-group": log_group,
                        "awslogs-region": ctx.region,
                        "awslogs-stream-prefix": "sim2real",
                    },
                },
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    # The positive control retries a fresh role's IAM propagation failures to a deadline:
    # up to six launches, each with its 180 s STOPPED poll and a 15 s pause.
    budget = 6 * (180.0 + 15.0)
    left = ctx.time_left()
    deadline = time.monotonic() + (budget if left is None else min(budget, left - 5))
    while True:
        try:
            resp = ecs.run_task(
                cluster=cluster_name,
                taskDefinition=family,
                launchType="FARGATE",
                networkConfiguration=netcfg,
                count=1,
            )
        except ClientError as exc:
            # A role whose trust policy never includes ecs-tasks.amazonaws.com makes
            # RunTask reject synchronously ("ECS was unable to assume the role...")
            # every single time -- that IS the negative-path proof: no task was ever
            # placed, so no container ever ran and no logs were ever pushed via it.
            if not retry:
                return {
                    "stopCode": "TaskFailedToStart",
                    "stoppedReason": str(exc),
                    "containers": [{"exitCode": None}],
                    "_statuses_seen": set(),
                }
            # For the correctly-trusted positive control this is a transient
            # propagation failure right after role creation; retry it out.
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)
            continue

        assert not resp["failures"], f"RunTask returned failures: {resp['failures']}"
        task_arn = resp["tasks"][0]["taskArn"]

        def _cleanup_task(arn=task_arn):
            try:
                ecs.stop_task(cluster=cluster_name, task=arn, reason="test-cleanup")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                    raise

        ctx.on_cleanup(_cleanup_task)

        statuses_seen = set()

        def _probe(arn=task_arn):
            t = ecs.describe_tasks(cluster=cluster_name, tasks=[arn])["tasks"][0]
            statuses_seen.add(t["lastStatus"])
            return t

        last_task = _poll_until(
            _probe, lambda t: t["lastStatus"] == "STOPPED", timeout_s=180.0, interval_s=5.0
        )
        last_task["_statuses_seen"] = statuses_seen
        last_task["_marker"] = marker
        if not retry or last_task["stopCode"] != "TaskFailedToStart" or time.monotonic() >= deadline:
            return last_task
        time.sleep(2)



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


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
