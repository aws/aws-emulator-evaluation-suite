"""run-task-platform-incompatibility-rejected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "run-task-platform-incompatibility-rejected"
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


def _reject(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    over-permissive target accepting the withdrawn platform version must not read as a
    downstream code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected RunTask to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RunTask refuses the withdrawn Fargate platform version 1.3.0 with AccessDeniedException for any
    task definition, while the same task definition runs on platform version LATEST."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    # Standalone Fargate RunTask relies on the ECS service-linked role for ENI mgmt.
    try:
        ctx.client("iam").create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as exc:  # already-exists (InvalidInput) is success
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, name))
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
    net_cfg = {
        "awsvpcConfiguration": {"subnets": subnets[:1], "securityGroups": [sg], "assignPublicIp": "ENABLED"}
    }

    error = _reject(
        lambda: ecs.run_task(
            cluster=name,
            taskDefinition=td["taskDefinitionArn"],
            launchType="FARGATE",
            platformVersion="1.3.0",
            networkConfiguration=net_cfg,
        )
    )
    assert error.get("Code") == "AccessDeniedException", (
        f"expected the withdrawn platformVersion 1.3.0 RunTask to be rejected with "
        f"AccessDeniedException, got {error.get('Code')!r}"
    )
    assert error.get("Message") == "You do not have authorization to access the specified platform.", (
        f"expected the specific platform-withdrawal message, got {error.get('Message')!r} — a "
        f"different message could mean the account lacks RunTask permission entirely, which is a "
        f"different failure than the platform-version withdrawal this check asserts"
    )

    # Effect absent: the rejected call started no task on the cluster.
    task_arns = ecs.list_tasks(cluster=name)["taskArns"]
    assert task_arns == [], f"expected no tasks placed by the rejected RunTask, found {task_arns}"

    # Positive control: the SAME task definition on the compatible LATEST platform version must
    # actually be runnable — proving the rejection above is the platform-version withdrawal, not a
    # blanket inability to RunTask in this account.
    try:
        run_resp = ecs.run_task(
            cluster=name,
            taskDefinition=td["taskDefinitionArn"],
            launchType="FARGATE",
            platformVersion="LATEST",
            count=1,
            networkConfiguration=net_cfg,
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "AccessDeniedException":
            raise AssertionError(
                "caller is not authorized to RunTask Fargate in this account, so the compatible-"
                "platform sanity run cannot be exercised"
            ) from None
        raise
    assert not run_resp.get("failures"), (
        f"expected the same task definition to run fine on a compatible platform version, "
        f"got failures: {run_resp.get('failures')}"
    )
    task_arn = run_resp["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=name, task=task_arn, reason="behavioral-cleanup"))

    # Terminal read: an independent DescribeTasks call — a different operation than the RunTask
    # that mutated — confirms the task actually reached a live state at the destination, rather
    # than trusting RunTask's own response.
    described = ecs.describe_tasks(cluster=name, tasks=[task_arn])["tasks"]
    assert described and described[0]["lastStatus"] in ("PROVISIONING", "PENDING", "RUNNING"), (
        f"expected an independent DescribeTasks read to confirm the compatible-platform task is "
        f"alive, got {described!r}"
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
