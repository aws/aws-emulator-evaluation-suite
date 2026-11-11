"""run-task-capacity-provider-strategy-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "run-task-capacity-provider-strategy-conflict-rejected"
GROUP = 'capacity-provider'
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


def _refusal(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because a target accepting what AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ensure_ecs_slr(ctx):
    """Create AWSServiceRoleForECS, the service-linked role ECS assumes to attach an awsvpc
    task's ENI.

    A prerequisite is the check's job, not the account's. CreateService creates this role
    implicitly; RunTask does NOT, so in an account that has never used ECS every Fargate
    RunTask fails with InvalidParameterException "Unable to assume the service linked role".
    Already-exists (InvalidInput) is success, not an error condition.

    A freshly minted role is not assumable at once, and there is no read API that reports
    "assumable" — the only observable signal is the RunTask call itself, so readiness is
    confirmed at first use (`_run_task_awaiting_slr` below), not by a blind wait here.

    NO teardown is registered, and that is deliberate rather than an oversight: the role is
    account-level, free, and shared by every ECS workload in the account, and
    DeleteServiceLinkedRole is asynchronous and fails while any ECS resource still references
    it — so a teardown here would either be a no-op or would break a sibling check running
    after this one.
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


def _run_task_awaiting_slr(fn, *, timeout_s=120, interval_s=10):
    """Retry a RunTask call while the ECS service-linked role is still propagating.

    Real AWS reports that transient state as InvalidParameterException "Unable to assume
    the service linked role" — indistinguishable, by code alone, from a genuinely missing
    role. Any other error is a real result and is raised immediately, never retried.
    """
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "InvalidParameterException" and (
                "service linked role" in err.get("Message", "").lower()
            ):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(
        f"the ECS service-linked role never became assumable within {timeout_s}s"
    ) from last_exc

# ===== end helpers =====


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask refuses launchType together with capacityProviderStrategy, and a provider not associated
    with the cluster, creating no task; a task placed by the associated FARGATE provider carries
    capacityProviderName as well as launchType, while a launchType-placed task has no capacityProviderName."""
    ecs = ctx.client("ecs")
    cluster = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(
        clusterName=cluster,
        capacityProviders=["FARGATE"],
        defaultCapacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
    )
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster))
    described_cluster = ecs.describe_clusters(clusters=[cluster])["clusters"][0]
    assert described_cluster.get("capacityProviders") == ["FARGATE"], (
        f"only FARGATE must be associated with this cluster, got {described_cluster.get('capacityProviders')}"
    )

    td_arn = ecs.register_task_definition(
        family=ctx.unique_name("sim2real-behav-ecs-taskdef-fg-"),
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sh", "-c", "sleep 600"],
            }
        ],
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td_arn]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td_arn))

    _ensure_ecs_slr(ctx)

    subnets, sg = _fargate_network(ctx)
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": subnets[:1],
            "securityGroups": [sg],
            "assignPublicIp": "ENABLED",
        }
    }

    def _tasks() -> list[str]:
        return ecs.list_tasks(cluster=cluster)["taskArns"]

    assert _tasks() == [], f"the cluster must start with no tasks, got {_tasks()}"

    # (1) launchType and capacityProviderStrategy are mutually exclusive.
    both_code, both_message = _refusal(
        lambda: ecs.run_task(
            cluster=cluster,
            taskDefinition=td_arn,
            launchType="FARGATE",
            capacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
            count=1,
            networkConfiguration=net_cfg,
        )
    )
    assert both_code == "InvalidParameterException", (
        "specifying BOTH launchType and capacityProviderStrategy must be rejected with "
        f"InvalidParameterException, got {both_code!r}"
    )
    assert both_message == "You may choose a capacity provider or a launch type but not both.", f"refusal message {both_message!r}"
    assert _tasks() == [], (
        f"the rejected RunTask must not have created a task, got {_tasks()}"
    )

    # (2) A provider that is not associated with the cluster cannot be used.
    unassociated_code, unassociated_message = _refusal(
        lambda: ecs.run_task(
            cluster=cluster,
            taskDefinition=td_arn,
            capacityProviderStrategy=[{"capacityProvider": "FARGATE_SPOT", "weight": 1}],
            count=1,
            networkConfiguration=net_cfg,
        )
    )
    # ECS refuses an unassociated capacity provider with InvalidParameterException.
    assert unassociated_code == "InvalidParameterException", (
        "using a capacity provider that is not associated with the cluster must be refused with "
        f"InvalidParameterException, got {unassociated_code!r}"
    )
    assert unassociated_message == "The specified capacity provider strategy cannot contain a capacity provider that is not associated with the cluster. Associate the capacity provider with the cluster or specify a valid capacity provider and try again.", f"refusal message {unassociated_message!r}"
    assert _tasks() == [], (
        f"the rejected RunTask must not have created a task, got {_tasks()}"
    )

    # (3) Control: the associated provider works, and stamps capacityProviderName.
    resp = _run_task_awaiting_slr(
        lambda: ecs.run_task(
            cluster=cluster,
            taskDefinition=td_arn,
            capacityProviderStrategy=[{"capacityProvider": "FARGATE", "weight": 1}],
            count=1,
            networkConfiguration=net_cfg,
        )
    )
    assert not resp.get("failures"), f"the control RunTask must succeed, got {resp.get('failures')}"
    task_arn = resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: ecs.stop_task(cluster=cluster, task=task_arn, reason="behavioral-cleanup")
    )
    placed = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0],
        lambda t: t.get("capacityProviderName") is not None,
        timeout_s=300,
        interval_s=10,
        description="the placed task is stamped with the capacity provider that placed it",
    )
    assert placed.get("capacityProviderName") == "FARGATE", (
        f"expected capacityProviderName 'FARGATE', got {placed.get('capacityProviderName')!r}"
    )
    # A capacity-provider-placed task carries BOTH fields: launchType is DERIVED from the
    # provider rather than left unset.
    assert placed.get("launchType") == "FARGATE", (
        "a task placed by the FARGATE capacity provider must also report the launchType that "
        f"provider implies, got {placed.get('launchType')!r}"
    )
    # And already in the RunTask response, before the task is placed — so the stamp is not a
    # late-materialising describe_tasks artifact.
    assert resp["tasks"][0].get("capacityProviderName") == "FARGATE", resp["tasks"][0]
    assert resp["tasks"][0].get("launchType") == "FARGATE", resp["tasks"][0]

    # (4) The DISCRIMINATOR, in the other direction: the same task definition launched with
    # launchType alone must carry launchType and NO capacityProviderName. This is what makes
    # capacityProviderName load-bearing — without this leg an emulator that stamps
    # capacityProviderName='FARGATE' on every Fargate task passes leg 3 unchanged.
    lt_resp = ecs.run_task(
        cluster=cluster,
        taskDefinition=td_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration=net_cfg,
    )
    assert not lt_resp.get("failures"), f"the launchType RunTask must succeed, got {lt_resp.get('failures')}"
    lt_arn = lt_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(
        lambda: ecs.stop_task(cluster=cluster, task=lt_arn, reason="behavioral-cleanup")
    )
    assert lt_resp["tasks"][0].get("launchType") == "FARGATE", lt_resp["tasks"][0]
    assert "capacityProviderName" not in lt_resp["tasks"][0], (
        "a task placed by launchType was NOT placed by a capacity provider, so ECS must omit "
        f"capacityProviderName entirely; got {lt_resp['tasks'][0].get('capacityProviderName')!r}"
    )
    lt_placed = ecs.describe_tasks(cluster=cluster, tasks=[lt_arn])["tasks"][0]
    assert lt_placed.get("launchType") == "FARGATE", lt_placed.get("launchType")
    assert "capacityProviderName" not in lt_placed, (
        "describe_tasks must likewise omit capacityProviderName for a launchType-placed task; "
        f"got {lt_placed.get('capacityProviderName')!r}"
    )
    # Both tasks exist and are distinct, so leg 4 did not simply re-read leg 3's task.
    assert lt_arn != task_arn, (lt_arn, task_arn)
    assert set(_tasks()) == {task_arn, lt_arn}, (_tasks(), task_arn, lt_arn)


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
