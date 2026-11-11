"""submit-attachment-state-change-updates-attachment-status."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "submit-attachment-state-change-updates-attachment-status"
GROUP = "server-side"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SubmitAttachmentStateChanges moves a Fargate task's ENI attachment from ATTACHING (the only
    status AWS accepts the transition from) to ATTACHED, as reported by DescribeTasks.
    """
    ecs = ctx.client("ecs")
    subnet_id, sg_id = _fargate_network(ctx)

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    cluster_arn = ecs.create_cluster(clusterName=cluster_name)["cluster"]["clusterArn"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_arn))

    family = ctx.unique_name("sim2real-behav-td-")
    td_arn = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "essential": True,
                "command": ["sleep", "120"],
            }
        ],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    # Real ECS attachments progress through an ordered state machine
    # (PRECREATED -> CREATED -> ATTACHING -> ATTACHED). SubmitAttachmentStateChanges only
    # accepts the terminal statuses ("ATTACHED"/"DETACHED") as the reported value, but real
    # AWS also validates that the transition is legal for the attachment's *current* status:
    # jumping straight from an early status such as "PRECREATED"/"CREATED" to "ATTACHED"
    # raises InvalidParameterException ("Invalid state transition for attachment"). Only the
    # adjacent predecessor status, "ATTACHING", may be legally transitioned to "ATTACHED".
    #
    # On real AWS the pace of the Fargate provisioning pipeline's own progression through this
    # state machine varies run-to-run (capacity, image caching, etc.): sometimes it lingers at
    # "PRECREATED"/"CREATED" for a while before reaching "ATTACHING", and sometimes it can race
    # past "ATTACHING" to "ATTACHED" on its own between our polls. Neither outcome means our
    # explicit-transition assertion is wrong - it means a given task's timing didn't cooperate.
    # So we retry with a fresh task (bounded) until one attempt actually lands us in the
    # "ATTACHING" window, and only then perform + verify our own explicit ATTACHING -> ATTACHED
    # transition, well before the real pipeline would normally complete the attach on its own.
    # The whole retry loop (across all attempts) must stay comfortably inside the harness's
    # overall check-execution budget. Rather than giving every attempt a fixed, generous
    # per-attempt timeout (which, multiplied across retries, could itself exceed the harness
    # deadline and turn a legitimate-but-slow attach into a hard timeout of the *check itself*
    # rather than a clean assertion failure), track one shared overall deadline and shrink each
    # attempt's poll budget to whatever time remains.
    overall_deadline = time.monotonic() + 240.0
    last_error: Exception | None = None
    for attempt in range(1, 4):
        remaining = overall_deadline - time.monotonic()
        if remaining <= 10:
            # Not enough budget left for a meaningful attempt; stop retrying rather than risk
            # overrunning the harness's own timeout.
            break

        run_resp = ecs.run_task(
            cluster=cluster_arn,
            taskDefinition=td_arn,
            launchType="FARGATE",
            count=1,
            networkConfiguration={
                "awsvpcConfiguration": {"subnets": [subnet_id], "securityGroups": [sg_id], "assignPublicIp": "ENABLED"}
            },
        )
        if run_resp.get("failures"):
            raise AssertionError(f"RunTask reported failures: {run_resp['failures']}")
        task_arn = run_resp["tasks"][0]["taskArn"]
        ctx.on_cleanup(lambda task_arn=task_arn: ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="test-cleanup"))

        try:
            # A fresh Fargate ENI attachment can take over a minute to reach ATTACHING; bound
            # each attempt by the shared deadline.
            attempt_timeout = min(150.0, overall_deadline - time.monotonic())
            attachment = _poll_until(
                lambda: _first_attachment(ecs, cluster_arn, task_arn),
                lambda a: a is not None and a.get("status") in ("ATTACHING", "ATTACHED"),
                timeout_s=attempt_timeout,
                interval_s=1.0,
            )
        except AssertionError as err:
            last_error = err
            continue

        if attachment.get("status") != "ATTACHING":
            # The real pipeline's own attach already advanced past ATTACHING before we could
            # observe/act on it - retry with a fresh task rather than weaken what we assert.
            last_error = AssertionError(
                f"attempt {attempt}: attachment reached {attachment.get('status')!r} "
                "before an ATTACHING window could be observed"
            )
            continue

        attachment_arn = attachment["id"]
        ecs.submit_attachment_state_changes(
            cluster=cluster_arn, attachments=[{"attachmentArn": attachment_arn, "status": "ATTACHED"}]
        )

        final_status = _poll_until(
            lambda: _first_attachment(ecs, cluster_arn, task_arn)["status"],
            lambda status: status == "ATTACHED",
            timeout_s=8,
            interval_s=0.5,
        )
        assert final_status == "ATTACHED", f"expected attachment status ATTACHED, got {final_status!r}"
        break
    else:
        raise last_error or AssertionError("attachment never reached ATTACHING across retries")


# ===== helpers =====
def _first_attachment(ecs, cluster_arn: str, task_arn: str):
    task = ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn])["tasks"][0]
    attachments = task.get("attachments") or []
    return attachments[0] if attachments else None


def _fargate_network(ctx):
    """(subnet, security group) for Fargate (awsvpc) tasks from the run's shared network (ctx.network), the
    same on every target; the run owns and deletes the network."""
    net = ctx.network()
    return net.subnet_ids[0], net.security_group_id


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
