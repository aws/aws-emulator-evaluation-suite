"""eni-attachment-reaches-attached."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "eni-attachment-reaches-attached"
GROUP = 'task-state-change'
SERVICES = ['ecs']


FARGATE_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "essential": True,
        "command": ["sleep", "600"],
    }
]


def _error(fn):
    """Call fn() and return its botocore error (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
    """(subnets, security group) for Fargate (awsvpc) tasks from the run's shared network."""
    net = ctx.network()
    return list(net.subnet_ids), net.security_group_id


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Fargate task's ENI attachment reaches ATTACHED; replaying the ATTACHED state change is a
    no-op (no status change, no second record); SubmitAttachmentStateChanges on an unknown
    cluster fails with ClientException."""
    ecs = ctx.client("ecs")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    subnets, sg = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg], "assignPublicIp": "ENABLED"}
    }

    cluster = ecs.create_cluster(clusterName=ctx.unique_name("sim2real-behav-ecs-cluster-"))["cluster"]
    name = cluster["clusterName"]
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))

    # overly-permissive boundary: unknown cluster with a well-formed attachment ARN.
    bogus_cluster = ctx.unique_name("no-such-cluster-")
    code, message = _error(
        lambda: ecs.submit_attachment_state_changes(
            cluster=bogus_cluster,
            attachments=[
                {
                    "attachmentArn": f"arn:aws:ecs:{ctx.region}:{account_id}:attachment/"
                    "00000000-0000-0000-0000-000000000000",
                    "status": "ATTACHED",
                }
            ],
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code}"
    assert message == "Cluster not found.", f"unexpected message: {message!r}"

    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
    )["taskDefinition"]
    td_arn = td["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    run_resp = ecs.run_task(
        cluster=name,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration=net_cfg,
    )
    assert not run_resp.get("failures"), f"unexpected RunTask failures: {run_resp.get('failures')}"
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=name, task=task_arn, reason="behavioral-cleanup"))

    def _task():
        # DescribeTasks is eventually consistent right after RunTask — the task
        # ARN can be briefly absent, so tolerate an empty list instead of
        # indexing [0] and let the poll retry.
        tasks = ecs.describe_tasks(cluster=name, tasks=[task_arn])["tasks"]
        return tasks[0] if tasks else None

    def _eni_attachment(t):
        if t is None:
            return None
        for att in t.get("attachments", []):
            if att.get("type") == "ElasticNetworkInterface":
                return att
        return None

    attached_task = _poll_until(
        _task,
        lambda t: (a := _eni_attachment(t)) is not None and a.get("status") == "ATTACHED",
        timeout_s=180,
    )
    attachment = _eni_attachment(attached_task)
    assert attachment is not None and attachment["status"] == "ATTACHED", (
        f"expected an ElasticNetworkInterface attachment in ATTACHED status, got {attachment!r}"
    )
    full_attachment_arn = f"arn:aws:ecs:{ctx.region}:{account_id}:attachment/{attachment['id']}"

    # Idempotent duplicate replay of the already-applied ATTACHED signal.
    ecs.submit_attachment_state_changes(
        cluster=name,
        attachments=[{"attachmentArn": full_attachment_arn, "status": "ATTACHED"}],
    )

    still_task = _task()
    still_attachment = _eni_attachment(still_task)
    assert still_attachment is not None and still_attachment["status"] == "ATTACHED", (
        f"a duplicate ATTACHED replay must not perturb the attachment status, got {still_attachment}"
    )
    assert len(still_task.get("attachments", [])) == len(attached_task.get("attachments", [])), (
        "a duplicate attachment state-change replay must not create a second attachment record"
    )


def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services or tasks remain, and a running task's ENI blocks
    deleting the network.
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
