"""access-denied-across-mutating-ops."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "access-denied-across-mutating-ops"
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
    """Return the (code, message) of the error fn() raises; a success raises, since real AWS denies
    these calls."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be denied, but it succeeded and returned {result!r}")


def _create_restricted_client(ctx, service, policy_document, *, timeout_s=90):
    """Return (client, role_name, session_arn) signing as a fresh role under *policy_document*."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-ecs-denied-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    iam.put_role_policy(
        RoleName=role_name, PolicyName="restriction", PolicyDocument=json.dumps(policy_document)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="restriction"))

    session_name = ctx.unique_name("sess-")

    def _try_assume():
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except Exception as exc:  # noqa: BLE001 — IAM trust/policy propagation lag
            return exc

    creds = _poll_until(
        _try_assume,
        lambda r: not isinstance(r, Exception),
        timeout_s=timeout_s,
        interval_s=5,
        description="IAM role trust policy propagates enough for AssumeRole",
    )
    client = ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    session_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"
    return client, role_name, session_arn


def _denied_message(session_arn, action, resource):
    return (
        f"User: {session_arn} is not authorized to perform: {action} on resource: {resource} "
        "with an explicit deny in an identity-based policy"
    )


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role whose policy allows * but denies four ECS mutations gets AccessDeniedException with
    the exact message on CreateCluster, DeleteCluster, UpdateService and RegisterTaskDefinition,
    with no effect; dropping the RegisterTaskDefinition deny lets the identical call succeed."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    # CreateService (used below to set up the UpdateService denial) needs the ECS
    # service-linked role to exist in the account; ensure it's present.
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except Exception:  # noqa: BLE001 — already-exists (InvalidInput) is success
        pass
    denied_actions = [
        "ecs:CreateCluster",
        "ecs:DeleteCluster",
        "ecs:UpdateService",
        "ecs:RegisterTaskDefinition",
    ]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": denied_actions, "Resource": "*"},
        ],
    }
    restricted, role_name, session_arn = _create_restricted_client(ctx, "ecs", policy)
    ecs_arn = f"arn:aws:ecs:{ctx.region}:{ctx.account}"

    # --- CreateCluster: positive control (unrestricted) precedes the break.
    cluster_name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))
    control = ecs.describe_clusters(clusters=[cluster_name])["clusters"]
    assert control and control[0]["status"] == "ACTIVE", (
        f"positive control: an unrestricted CreateCluster must actually produce an ACTIVE cluster, "
        f"got {control}"
    )

    denied_cluster_name = ctx.unique_name("denied-")
    code, message = _error(lambda: restricted.create_cluster(clusterName=denied_cluster_name))
    assert code == "AccessDeniedException", f"expected AccessDeniedException on CreateCluster, got {code}"
    expected = _denied_message(session_arn, "ecs:CreateCluster", f"{ecs_arn}:cluster/{denied_cluster_name}")
    assert message == expected, f"CreateCluster: unexpected message {message!r}"
    absent = ecs.describe_clusters(clusters=[denied_cluster_name])["clusters"]
    assert not absent, (
        f"CreateCluster was denied but a cluster named {denied_cluster_name!r} exists: {absent}"
    )

    # --- DeleteCluster: the unrestricted create above is the positive control for this call too.
    code, message = _error(lambda: restricted.delete_cluster(cluster=cluster_name))
    assert code == "AccessDeniedException", f"expected AccessDeniedException on DeleteCluster, got {code}"
    expected = _denied_message(session_arn, "ecs:DeleteCluster", f"{ecs_arn}:cluster/{cluster_name}")
    assert message == expected, f"DeleteCluster: unexpected message {message!r}"
    still = ecs.describe_clusters(clusters=[cluster_name])["clusters"]
    assert still and still[0]["status"] == "ACTIVE", (
        f"expected the cluster to remain ACTIVE after the denied DeleteCluster, got {still}"
    )

    subnets = _default_subnets(ec2, ctx=ctx)
    sg = _default_sg(ec2, ctx=ctx)
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-fg-")
    td = ecs.register_task_definition(
        family=family,
        containerDefinitions=FARGATE_CONTAINER_DEFS,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"]))
    service_name = ctx.unique_name("sim2real-behav-ecs-svc-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=td["taskDefinitionArn"],
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": subnets[:1],
                "securityGroups": [sg],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))

    # --- UpdateService: positive control (unrestricted, 1 -> 2) precedes the break.
    ecs.update_service(cluster=cluster_name, service=service_name, desiredCount=2)
    control_service = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"][0]
    assert control_service["desiredCount"] == 2, (
        f"positive control: an unrestricted UpdateService must actually change desiredCount, "
        f"got {control_service['desiredCount']}"
    )

    code, message = _error(
        lambda: restricted.update_service(cluster=cluster_name, service=service_name, desiredCount=3)
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException on UpdateService, got {code}"
    expected = _denied_message(
        session_arn, "ecs:UpdateService", f"{ecs_arn}:service/{cluster_name}/{service_name}"
    )
    assert message == expected, f"UpdateService: unexpected message {message!r}"
    still_service = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"][0]
    assert still_service["desiredCount"] == 2, (
        f"expected desiredCount to remain unchanged after the denied UpdateService, "
        f"got {still_service['desiredCount']}"
    )

    # --- RegisterTaskDefinition: positive control (the Fargate registration above), break, effect
    #     absent, then restore the grant and prove the identical call now succeeds.
    denied_family = ctx.unique_name("denied-td-")
    register_kwargs = dict(
        family=denied_family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 64,
                "memory": 128,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    code, message = _error(lambda: restricted.register_task_definition(**register_kwargs))
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException on RegisterTaskDefinition, got {code}"
    )
    expected = _denied_message(
        session_arn, "ecs:RegisterTaskDefinition", f"{ecs_arn}:task-definition/{denied_family}:*"
    )
    assert message == expected, f"RegisterTaskDefinition: unexpected message {message!r}"
    absent_td_code, absent_td_message = _error(
        lambda: ecs.describe_task_definition(taskDefinition=denied_family)
    )
    assert absent_td_code == "ClientException", (
        f"RegisterTaskDefinition was denied but describe_task_definition for {denied_family!r} "
        f"returned {absent_td_code}, expected ClientException (no such task definition family)"
    )
    assert absent_td_message == "Unable to describe task definition.", (
        f"DescribeTaskDefinition: unexpected message {absent_td_message!r}"
    )

    # One restore leg stands for all four denials: they share the same role and policy.
    restored_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {
                "Effect": "Deny",
                "Action": [a for a in denied_actions if a != "ecs:RegisterTaskDefinition"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="restriction", PolicyDocument=json.dumps(restored_policy)
    )

    def _try_register():
        try:
            return restricted.register_task_definition(**register_kwargs)["taskDefinition"]
        except ClientError as exc:
            return exc

    restored_td = _poll_until(
        _try_register,
        lambda r: not isinstance(r, Exception),
        timeout_s=60,
        interval_s=5,
        description="removing RegisterTaskDefinition from the Deny statement restores the identical call",
    )
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[restored_td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=restored_td["taskDefinitionArn"]))
    assert restored_td["family"] == denied_family, (
        f"restoring the grant must let the identical RegisterTaskDefinition call through; "
        f"got family {restored_td['family']!r}"
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
