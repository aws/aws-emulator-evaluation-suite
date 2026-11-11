"""concurrent-service-update-deployment-converges."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "concurrent-service-update-deployment-converges"
GROUP = 'concurrency'
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


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _register_fargate_td(ctx, ecs):
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
    return td


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateService (desiredCount) racing StopServiceDeployment on the in-flight deployment
    resolves to one consistent service state: no corrupted record, no two current deployments,
    and a desiredCount within the raced values."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))
    td1 = _register_fargate_td(ctx, ecs)
    td2 = _register_fargate_td(ctx, ecs)
    subnets, sg = _fargate_network(ctx)

    svc_name = ctx.unique_name("sim2real-behav-ecs-svc-")
    ecs.create_service(
        cluster=name,
        serviceName=svc_name,
        taskDefinition=td1["taskDefinitionArn"],
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets[:1],
                "securityGroups": [sg],
                "assignPublicIp": "ENABLED",
            }
        },
        deploymentConfiguration={"strategy": "BLUE_GREEN"},
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=name, service=svc_name, force=True))

    # Let the initial deployment settle so we cleanly isolate the SECOND
    # (UpdateService-triggered) deployment as the one we race against.
    _poll_until(
        lambda: ecs.list_service_deployments(cluster=name, service=svc_name)["serviceDeployments"],
        lambda deployments: any(d["status"] in ("SUCCESSFUL", "STOPPED") for d in deployments),
        timeout_s=180,
        interval_s=5,
        description="the initial BLUE_GREEN deployment reaches a terminal status",
    )

    ecs.update_service(cluster=name, service=svc_name, taskDefinition=td2["taskDefinitionArn"])

    def _find_in_progress():
        deployments = ecs.list_service_deployments(cluster=name, service=svc_name)[
            "serviceDeployments"
        ]
        in_progress = [d for d in deployments if d["status"] == "IN_PROGRESS"]
        return in_progress[0] if in_progress else None

    new_dep = _poll_until(
        _find_in_progress,
        lambda d: d is not None,
        timeout_s=60,
        interval_s=3,
        description="UpdateService creates a new IN_PROGRESS ServiceDeployment",
    )
    deployment_arn = new_dep["serviceDeploymentArn"]

    def _update_desired_count():
        return ecs.update_service(cluster=name, service=svc_name, desiredCount=2)

    def _stop_deployment():
        return ecs.stop_service_deployment(serviceDeploymentArn=deployment_arn, stopType="ROLLBACK")

    results = _run_concurrent([_update_desired_count, _stop_deployment], timeout_s=60)
    # A losing racer may fail with a conflict/validation code or a transient
    # throttle/in-progress code; neither means corrupted state (the settle
    # invariants below check that).
    _acceptable_racer_failures = (
        "ConflictException",
        "InvalidParameterException",
        "ClientException",
        "ThrottlingException",
        "Throttling",
        "TooManyRequestsException",
        "RequestLimitExceeded",
        "ServerException",
        "InternalServerError",
        "InternalFailure",
        "ServiceUnavailable",
        "ServiceUnavailableException",
        "UpdateInProgressException",
    )
    for r in results:
        if isinstance(r, BaseException):
            code = _concurrent_error_codes([r])[0]
            assert code in _acceptable_racer_failures, (
                f"expected a losing racer (if any) to fail with a real conflict/validation or "
                f"transient code, got {code}"
            )

    final_svc = _poll_until(
        lambda: ecs.describe_services(cluster=name, services=[svc_name])["services"][0],
        lambda s: s["status"] == "ACTIVE",
        timeout_s=120,
        interval_s=5,
        description="the service settles back to ACTIVE after the race resolves",
    )
    assert final_svc["status"] == "ACTIVE", f"expected the service to remain ACTIVE, got {final_svc}"
    assert final_svc["desiredCount"] in (1, 2), (
        f"expected desiredCount to cleanly settle to ONE of the raced values (1 unchanged, or 2 if "
        f"the racing UpdateService won), got {final_svc['desiredCount']} — a value outside that set "
        f"would indicate corrupted state"
    )

    deployments = ecs.list_service_deployments(cluster=name, service=svc_name)["serviceDeployments"]
    in_progress = [d for d in deployments if d["status"] == "IN_PROGRESS"]
    assert len(in_progress) <= 1, (
        f"expected at most ONE IN_PROGRESS deployment after the race settles, got {in_progress}"
    )


def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=780.0, interval_s=2.0):
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
