"""taskdef-revision-never-reused-after-deregister."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "taskdef-revision-never-reused-after-deregister"
GROUP = 'task-definition'
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


def _error(fn):
    """Call fn(); return its botocore (code, message). A call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ensure_ecs_slr(ctx):
    """Create AWSServiceRoleForECS, the service-linked role ECS assumes to attach an awsvpc
    task's ENI. The RunTask that needs it retries until the role is assumable.

    A prerequisite is the check's job, not the account's. CreateService creates this role
    implicitly; RunTask does NOT, so in an account that has never used ECS every Fargate
    RunTask fails with InvalidParameterException "Unable to assume the service linked role".
    Already-exists (InvalidInput) is success, not an error condition.

    No teardown is registered: the role is account-level, free and shared by every ECS
    workload, and DeleteServiceLinkedRole fails while any ECS resource still references it.
    """
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        if code not in ("InvalidInput", "InvalidInputException") or message != (
            "Service role name AWSServiceRoleForECS has been taken in this account, please try a different suffix."
        ):
            raise AssertionError(f"cannot create the ECS service-linked role: {exc}") from exc
        return

# ===== end helpers =====


@tags("axis:happy-path", "cap:c3", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A task-definition revision is immutable and its number is never reused: after revision 1 is
    deregistered (INACTIVE, still describable) the next registration is revision 3, and RunTask on
    the INACTIVE revision is refused with InvalidParameterException while revision 3 runs.
    """
    ecs = ctx.client("ecs")
    cluster = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster))

    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    image = "public.ecr.aws/docker/library/busybox:1.36"

    def _register(command: list[str], env_value: str) -> dict:
        td = ecs.register_task_definition(
            family=family,
            containerDefinitions=[
                {
                    "name": "app",
                    "image": image,
                    "essential": True,
                    "command": command,
                    "environment": [{"name": "SIM2REAL_REV", "value": env_value}],
                }
            ],
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",
        )["taskDefinition"]
        arn = td["taskDefinitionArn"]
        ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[arn]))
        ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=arn))
        return td

    rev1 = _register(["sh", "-c", "sleep 600"], "one")
    assert rev1["revision"] == 1, f"the first revision of a fresh family must be 1, got {rev1['revision']}"
    assert rev1["taskDefinitionArn"].endswith(f"{family}:1"), rev1["taskDefinitionArn"]

    rev2 = _register(["sh", "-c", "sleep 601"], "two")
    assert rev2["revision"] == 2, f"expected revision 2, got {rev2['revision']}"

    # Immutability: registering rev2 must not have mutated rev1.
    rev1_readback = ecs.describe_task_definition(taskDefinition=f"{family}:1")["taskDefinition"]
    rev1_container = rev1_readback["containerDefinitions"][0]
    assert rev1_container["command"] == ["sh", "-c", "sleep 600"], (
        f"registering a new revision must not mutate revision 1's command, got {rev1_container['command']}"
    )
    assert {"name": "SIM2REAL_REV", "value": "one"} in rev1_container["environment"], (
        f"revision 1's environment must be untouched, got {rev1_container['environment']}"
    )
    assert rev1_readback["status"] == "ACTIVE", rev1_readback["status"]

    # Deregister revision 1: readable, INACTIVE, deregisteredAt stamped.
    deregistered = ecs.deregister_task_definition(taskDefinition=f"{family}:1")["taskDefinition"]
    assert deregistered["status"] == "INACTIVE", deregistered["status"]
    inactive = ecs.describe_task_definition(taskDefinition=f"{family}:1")["taskDefinition"]
    assert inactive["status"] == "INACTIVE", inactive["status"]
    assert inactive.get("deregisteredAt") is not None, (
        f"a deregistered revision must carry deregisteredAt, got {inactive.get('deregisteredAt')!r}"
    )
    assert inactive["revision"] == 1, inactive["revision"]

    # The freed revision number must NOT be recycled.
    rev3 = _register(["sh", "-c", "sleep 602"], "three")
    assert rev3["revision"] == 3, (
        "revision numbers are a monotonic per-family counter: after deregistering revision 1 the "
        f"next registration must be 3, not a recycled 1 or 2, got {rev3['revision']}"
    )
    assert rev3["taskDefinitionArn"].endswith(f"{family}:3"), rev3["taskDefinitionArn"]

    active = ecs.list_task_definitions(familyPrefix=family, status="ACTIVE")["taskDefinitionArns"]
    assert rev1["taskDefinitionArn"] not in active, (
        f"the deregistered revision must not be listed ACTIVE, got {active}"
    )
    assert rev2["taskDefinitionArn"] in active and rev3["taskDefinitionArn"] in active, active
    listed_inactive = ecs.list_task_definitions(familyPrefix=family, status="INACTIVE")[
        "taskDefinitionArns"
    ]
    assert rev1["taskDefinitionArn"] in listed_inactive, (
        f"the deregistered revision must be listed INACTIVE, got {listed_inactive}"
    )

    _ensure_ecs_slr(ctx)

    subnets, sg = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": subnets[:1],
            "securityGroups": [sg],
            "assignPublicIp": "ENABLED",
        }
    }

    # An INACTIVE revision is readable but not runnable.
    def _run_inactive():
        ecs.run_task(
            cluster=cluster,
            taskDefinition=rev1["taskDefinitionArn"],
            launchType="FARGATE",
            count=1,
            networkConfiguration=net_cfg,
        )

    try:
        _run_inactive()
        raise AssertionError(
            "RunTask on an INACTIVE task definition revision must be refused, but it was "
            "accepted — an INACTIVE revision is readable, not runnable"
        )
    except ClientError as exc:
        error = exc.response.get("Error", {})
    code = error.get("Code")
    assert code == "InvalidParameterException", (
        "RunTask on an INACTIVE task definition revision must fail with "
        f"InvalidParameterException, got {code!r}"
    )
    # The message names the REASON, so the refusal cannot be satisfied by an unrelated
    # InvalidParameterException (e.g. a bad networkConfiguration).
    assert error.get("Message") == "TaskDefinition is inactive", (
        "the refusal must attribute itself to the revision's INACTIVE status, got "
        f"{error.get('Message')!r}"
    )
    # The same refusal by family:revision, so it is the revision's STATUS being rejected and
    # not the ARN spelling.
    by_family = _error(
        lambda: ecs.run_task(
            cluster=cluster,
            taskDefinition=f"{family}:1",
            launchType="FARGATE",
            count=1,
            networkConfiguration=net_cfg,
        )
    )
    assert by_family == ("InvalidParameterException", "TaskDefinition is inactive"), by_family
    assert ecs.list_tasks(cluster=cluster)["taskArns"] == [], (
        "the refused RunTask must not have created a task, got "
        f"{ecs.list_tasks(cluster=cluster)['taskArns']}"
    )

    # Control: the newest ACTIVE revision still runs. A freshly minted service-linked role is
    # not assumable at once, and ECS refuses RunTask with "Unable to assume the service linked
    # role" until it is, so the control is retried on that refusal alone within a bound.
    def _run_rev3():
        try:
            return ecs.run_task(
                cluster=cluster,
                taskDefinition=rev3["taskDefinitionArn"],
                launchType="FARGATE",
                count=1,
                networkConfiguration=net_cfg,
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "InvalidParameterException" and "service linked role" in err.get(
                "Message", ""
            ):
                return None
            raise

    resp = _poll_until(
        _run_rev3,
        lambda r: r is not None,
        timeout_s=120,
        interval_s=5,
        description="the service-linked role to become assumable for RunTask",
    )
    assert not resp.get("failures"), f"the control RunTask must succeed, got {resp.get('failures')}"
    task_arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: ecs.stop_task(cluster=cluster, task=task_arn, reason="behavioral-cleanup")
    )
    assert resp["tasks"][0]["taskDefinitionArn"] == rev3["taskDefinitionArn"], resp["tasks"][0]
    assert resp["tasks"][0]["desiredStatus"] == "RUNNING", resp["tasks"][0]["desiredStatus"]

    # Terminal read: an independent DescribeTasks call (not RunTask's own response) must
    # agree that the placed task is running revision 3 and is still alive.
    described = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"]
    assert described, f"an independent DescribeTasks read found no task for {task_arn}"
    assert described[0]["taskDefinitionArn"] == rev3["taskDefinitionArn"], (
        "an independent DescribeTasks read must confirm the control task is running the "
        f"non-recycled revision 3, got {described[0]['taskDefinitionArn']}"
    )
    assert described[0]["lastStatus"] != "STOPPED", (
        f"an independent DescribeTasks read must show the control task still alive, got {described[0]['lastStatus']!r}"
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
