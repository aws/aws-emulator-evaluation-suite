"""submit-attachment-state-changes-updates-eni-status."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "submit-attachment-state-changes-updates-eni-status"
GROUP = "server-side"
SERVICES = ["ecs"]

_NET_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-ecsx"},
]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SubmitAttachmentStateChanges with the full attachment ARN moves a Fargate task's ENI
    attachment from ATTACHING (reached on its own; AWS rejects PRECREATED -> ATTACHED and any
    status but ATTACHED) to ATTACHED, as reported by DescribeTasks.
    """
    ecs = ctx.client("ecs")
    infra = _provision_infra(ctx)
    cluster = infra["cluster"]
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    final_task_arn = None
    final_attachment_id = None
    last_race_error = None
    for _attempt in range(5):
        task = _launch_task(ctx, ecs, cluster, infra["task_def_arn"], infra["subnet_id"], infra["sg_id"])
        task_arn = task["taskArn"]

        attachments = task.get("attachments", [])
        eni_attachments = [a for a in attachments if a.get("type") == "ElasticNetworkInterface"]
        assert eni_attachments, f"expected an ElasticNetworkInterface attachment, got {attachments}"
        attachment = eni_attachments[0]
        attachment_id = attachment["id"]
        # RunTask always returns the attachment freshly created and not yet
        # attached -- PRECREATED is the state before the real Fargate
        # control plane has provisioned the ENI.
        assert attachment["status"] == "PRECREATED", attachment["status"]

        # Wait for the real platform's own automatic PRECREATED ->
        # ATTACHING step -- submitting ATTACHED while still PRECREATED is
        # rejected outright as an invalid state transition, regardless of
        # any race.
        observed = _poll_for_attachment_status(
            ecs, cluster, task_arn, attachment_id, {"ATTACHING", "ATTACHED"}, timeout=90, interval=2
        )
        if observed is None:
            last_race_error = "attachment never left PRECREATED within the poll budget"
            continue
        if observed["status"] == "ATTACHED":
            # The real platform's own agent report already completed the
            # ATTACHING -> ATTACHED transition before we could act.
            last_race_error = "the real platform reported ATTACHED itself before our submission"
            continue

        attachment_arn = f"arn:aws:ecs:{ctx.region}:{account_id}:attachment/{attachment_id}"
        try:
            ecs.submit_attachment_state_changes(
                cluster=cluster,
                attachments=[{"attachmentArn": attachment_arn, "status": "ATTACHED"}],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException":
                # Lost the ATTACHING -> ATTACHED race against the real
                # platform's own report landing first -- retry with a fresh
                # task instead of treating this as a real bug.
                last_race_error = exc
                continue
            raise

        final_task_arn = task_arn
        final_attachment_id = attachment_id
        break

    assert final_task_arn is not None, f"never won the race to submit ATTACHED first: {last_race_error}"

    after = _poll_for_attachment_status(ecs, cluster, final_task_arn, final_attachment_id, "ATTACHED")
    assert after is not None and after["status"] == "ATTACHED", after


# ===== helpers =====

def _poll_for_attachment_status(ecs, cluster, task_arn, attachment_id, want_statuses, timeout=60, interval=3):
    """Bounded poll for the attachment to reach one of `want_statuses`
    (a single status string or a set/collection of acceptable statuses),
    as reflected in DescribeTasks."""
    if isinstance(want_statuses, str):
        want_statuses = {want_statuses}
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        tasks = ecs.describe_tasks(cluster=cluster, tasks=[task_arn]).get("tasks", [])
        if tasks:
            last = next((a for a in tasks[0].get("attachments", []) if a["id"] == attachment_id), None)
            if last is not None and last["status"] in want_statuses:
                return last
        time.sleep(interval)
    return last


def _fargate_network(ctx):
    """(subnet, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return net.subnet_ids[0], net.security_group_id


def _create_task_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsx-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_NET_TAGS
    )["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _provision_infra(ctx):
    """Create the cluster/task-def/execution-role plumbing shared by every
    RunTask attempt, but do not launch any task yet -- callers need to be
    able to launch (and, if they lose the ATTACHED race, re-launch) tasks
    individually via `_launch_task`."""
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _fargate_network(ctx)
    exec_role_arn = _create_task_execution_role(ctx)

    cluster_name = ctx.unique_name("sim2real-ecsx-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": t["Key"], "value": t["Value"]} for t in _NET_TAGS])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    family = ctx.unique_name("sim2real-ecsx-taskdef-")
    reg = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023-minimal",
                "essential": True,
                "command": ["sleep", "300"],
            }
        ],
        tags=[{"key": t["Key"], "value": t["Value"]} for t in _NET_TAGS],
    )
    task_def_arn = reg["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    return {
        "cluster": cluster_name,
        "task_def_arn": task_def_arn,
        "subnet_id": subnet_id,
        "sg_id": sg_id,
    }


def _launch_task(ctx, ecs, cluster_name, task_def_arn, subnet_id, sg_id):
    """RunTask, retrying only for the transient IAM-eventual-consistency
    failure mode, and register cleanup to stop whatever task comes back.
    Returns the RunTask task dict as freshly returned (i.e. with its
    just-created, still-PRECREATED attachments) so the caller can act on it
    with minimal added latency."""
    tasks = []
    last_failures = None
    last_error = None
    deadline = time.monotonic() + 180.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    while True:
        try:
            resp = ecs.run_task(
                cluster=cluster_name,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration={
                    "awsvpcConfiguration": {
                        "subnets": [subnet_id],
                        "securityGroups": [sg_id],
                        "assignPublicIp": "ENABLED",
                    }
                },
            )
        except ClientError as exc:
            # Freshly-created IAM roles are eventually consistent -- ECS can
            # transiently fail to assume the just-created execution role for
            # a short window after CreateRole/AttachRolePolicy. Retry rather
            # than treat this as a real rejection.
            last_error = exc
            if exc.response["Error"]["Code"] == "ClientException" and "unable to assume the role" in str(exc):
                if time.monotonic() >= deadline:
                    break
                time.sleep(2)
                continue
            raise
        tasks = resp.get("tasks", [])
        if tasks:
            break
        last_failures = resp.get("failures")
        if time.monotonic() >= deadline:
            break
        time.sleep(2)
    if not tasks:
        raise AssertionError(f"RunTask never placed a task: failures={last_failures} last_error={last_error}")
    task = tasks[0]
    task_arn = task["taskArn"]

    def _stop_and_wait():
        try:
            ecs.stop_task(cluster=cluster_name, task=task_arn, reason="sim2real-cleanup")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            d = ecs.describe_tasks(cluster=cluster_name, tasks=[task_arn]).get("tasks", [])
            if not d or d[0]["lastStatus"] == "STOPPED":
                return
            time.sleep(3)

    ctx.on_cleanup(_stop_and_wait)

    return task



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
                if exc.response["Error"]["Code"] not in (
                    "ClusterNotFoundException",
                    "ServiceNotFoundException",
                    "ServiceNotActiveException",
                ):
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
