"""concurrent-run-task-idempotent-token."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-run-task-idempotent-token"
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


def _default_vpc_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _default_subnets(ec2, *, ctx):
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnets available in this account/region")
    return [s["SubnetId"] for s in subnets]


def _default_sg(ec2, *, ctx):
    vpc_id = _default_vpc_id(ec2, ctx=ctx)
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available in this account/region")
    return sgs[0]["GroupId"]


def _delete_cluster_retry(ecs, name, *, timeout_s=45):
    import time
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            _drain_and_delete_ecs_cluster(ecs, name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("ClusterContainsTasksException", "ClusterContainsContainerInstancesException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)


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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent RunTask calls sharing one clientToken each either succeed (dedup is best-effort,
    so racers may land on distinct tasks) or get InvalidParameterException naming the token
    INACTIVE, and every reported task is visible via ListTasks: no phantom tasks."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _delete_cluster_retry(ecs, name))
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
    subnets = _default_subnets(ec2, ctx=ctx)
    sg = _default_sg(ec2, ctx=ctx)
    token = ctx.unique_name("race-token-")
    net_cfg = {
        "awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg], "assignPublicIp": "ENABLED"}
    }

    def _attempt():
        return ecs.run_task(
            cluster=name,
            taskDefinition=td["taskDefinitionArn"],
            launchType="FARGATE",
            count=1,
            networkConfiguration=net_cfg,
            clientToken=token,
        )

    results = _run_concurrent([_attempt for _ in range(5)], timeout_s=90)

    task_arns = set()
    for r in results:
        if isinstance(r, BaseException):
            from botocore.exceptions import ClientError
            assert isinstance(r, ClientError), (
                f"a losing concurrent RunTask racer must fail with a ClientError from the "
                f"token race, not {type(r).__name__}: {r!r}"
            )
            error = r.response.get("Error", {})
            code = error.get("Code")
            message = error.get("Message", "")
            # The refusal message embeds run-specific values, so only its stable parts are matched.
            assert code == "InvalidParameterException" and "Cluster scoped token" in message and "INACTIVE" in message, (
                "a losing racer must fail with the specific cluster-scoped-token-inactive "
                f"InvalidParameterException, got {code}: {message!r}"
            )
            continue
        assert not r.get("failures"), f"unexpected RunTask failures: {r.get('failures')}"
        assert len(r["tasks"]) == 1, f"expected exactly one task per successful RunTask response, got {r['tasks']}"
        arn = r["tasks"][0]["taskArn"]
        task_arns.add(arn)
        ctx.on_cleanup(lambda a=arn: ecs.stop_task(cluster=name, task=a, reason="behavioral-cleanup"))

    assert task_arns, (
        f"expected at least one of the {len(results)} concurrent racers sharing a clientToken to "
        "actually launch a task; every racer instead failed with a token-inactive error"
    )

    listed = ecs.list_tasks(cluster=name)["taskArns"]
    for arn in task_arns:
        assert listed.count(arn) == 1, (
            f"task {arn} reported by a successful racer must appear exactly once in ListTasks, "
            f"got {listed.count(arn)} occurrences"
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
            except ClientError:
                pass
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
