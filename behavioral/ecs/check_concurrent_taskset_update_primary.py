"""concurrent-taskset-update-primary."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "concurrent-taskset-update-primary"
GROUP = 'overly-permissive'
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


def _retry_until_cluster_visible(fn, timeout_s=30.0):
    """Run fn, retrying while a just-created cluster is not yet visible to the service API."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            missing = exc.response.get("Error", {}).get("Code") == "ClusterNotFoundException"
            if not missing or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected with a ClientError, but it succeeded")


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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTaskSet (scaling A) racing UpdateServicePrimaryTaskSet (promoting B) leaves exactly one
    PRIMARY task set, never zero or two; promoting a nonexistent taskSet ARN is rejected."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    subnets = _default_subnets(ec2, ctx=ctx)
    sg = _default_sg(ec2, ctx=ctx)
    net_cfg = {
        "awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg], "assignPublicIp": "ENABLED"}
    }

    cluster_name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))
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
    svc_name = ctx.unique_name("sim2real-behav-ecs-ext-svc-")
    _retry_until_cluster_visible(
        lambda: ecs.create_service(
            cluster=cluster_name,
            serviceName=svc_name,
            desiredCount=0,
            deploymentController={"type": "EXTERNAL"},
        )
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=svc_name, force=True))

    ts_a = ecs.create_task_set(
        cluster=cluster_name,
        service=svc_name,
        taskDefinition=td["taskDefinitionArn"],
        scale={"value": 100.0, "unit": "PERCENT"},
        launchType="FARGATE",
        networkConfiguration=net_cfg,
    )["taskSet"]
    ts_a_arn = ts_a["taskSetArn"]
    ctx.on_cleanup(
        lambda: ecs.delete_task_set(cluster=cluster_name, service=svc_name, taskSet=ts_a_arn, force=True)
    )

    ts_b = ecs.create_task_set(
        cluster=cluster_name,
        service=svc_name,
        taskDefinition=td["taskDefinitionArn"],
        scale={"value": 100.0, "unit": "PERCENT"},
        launchType="FARGATE",
        networkConfiguration=net_cfg,
    )["taskSet"]
    ts_b_arn = ts_b["taskSetArn"]
    ctx.on_cleanup(
        lambda: ecs.delete_task_set(cluster=cluster_name, service=svc_name, taskSet=ts_b_arn, force=True)
    )

    ecs.update_service_primary_task_set(cluster=cluster_name, service=svc_name, primaryTaskSet=ts_a_arn)

    # Change one trailing character so the ARN stays well-formed: a malformed ARN gets
    # InvalidParameterException instead of TaskSetNotFoundException.
    bogus_arn = ts_a_arn[:-1] + ("0" if ts_a_arn[-1] != "0" else "1")
    code, message = _error(
        lambda: ecs.update_service_primary_task_set(
            cluster=cluster_name, service=svc_name, primaryTaskSet=bogus_arn
        )
    )
    assert code == "TaskSetNotFoundException", (
        f"expected TaskSetNotFoundException promoting a nonexistent taskSet ARN, got {code}"
    )
    expected_message = (
        f"Unable to find task set with id {bogus_arn.split('/', 3)[3]} on service {svc_name}."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still = ecs.describe_task_sets(cluster=cluster_name, service=svc_name, taskSets=[ts_a_arn])["taskSets"][0]
    assert still["status"] == "PRIMARY", (
        f"a rejected UpdateServicePrimaryTaskSet call must not disturb the existing PRIMARY task set, "
        f"got status={still['status']!r}"
    )

    def _update_scale_on_a():
        return ecs.update_task_set(
            cluster=cluster_name, service=svc_name, taskSet=ts_a_arn, scale={"value": 60.0, "unit": "PERCENT"}
        )

    def _promote_b():
        return ecs.update_service_primary_task_set(
            cluster=cluster_name, service=svc_name, primaryTaskSet=ts_b_arn
        )

    results = _run_concurrent([_update_scale_on_a, _promote_b], timeout_s=60)
    for r in results:
        assert not isinstance(r, BaseException), (
            f"expected both the orthogonal scale-update and promotion racers to succeed, got {r!r}"
        )

    described = ecs.describe_task_sets(
        cluster=cluster_name, service=svc_name, taskSets=[ts_a_arn, ts_b_arn]
    )["taskSets"]
    primaries = [t for t in described if t["status"] == "PRIMARY"]
    assert len(primaries) == 1, (
        f"expected EXACTLY ONE task set to be PRIMARY after the race resolves, got {len(primaries)}: "
        f"{described}"
    )
    assert primaries[0]["taskSetArn"] == ts_b_arn, (
        f"expected the explicitly-promoted task set B ({ts_b_arn}) to be the PRIMARY, "
        f"got {primaries[0]['taskSetArn']}"
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
