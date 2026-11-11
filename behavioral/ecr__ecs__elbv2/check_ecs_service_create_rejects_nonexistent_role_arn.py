"""ecs-service-create-rejects-nonexistent-role-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-service-create-rejects-nonexistent-role-arn"
GROUP = "iam-trust"
SERVICES = ["ecr", "ecs", "elbv2"]

_IMAGE = "public.ecr.aws/amazonlinux/amazonlinux:2023"
_EXEC_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A caller without iam:PassRole gets AccessDeniedException registering a task definition with a
    nonexistent role ARN, and nothing is registered; a permitted caller with a real role can
    register a task definition and create a service."""
    subnet_id, sg_id = _default_network(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }

    cluster = _create_cluster(ctx)
    good_role_arn = _create_execution_role(ctx)
    good_family = ctx.unique_name("sim2real-ecs-good-")
    good_td = ctx.client("ecs").register_task_definition(
        family=good_family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=good_role_arn,
        containerDefinitions=[{"name": "app", "image": _IMAGE, "essential": True, "command": ["sleep", "60"]}],
    )["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda t=good_td: _retire_task_def(ctx.client("ecs"), t))

    service_name = ctx.unique_name("sim2real-ecs-svc-")
    svc = ctx.client("ecs").create_service(
        cluster=cluster,
        serviceName=service_name,
        taskDefinition=good_td,
        desiredCount=0,
        launchType="FARGATE",
        networkConfiguration=net_cfg,
    )["service"]
    ctx.on_cleanup(lambda: ctx.client("ecs").delete_service(cluster=cluster, service=service_name, force=True))
    assert svc["status"] == "ACTIVE" and svc["serviceArn"], f"positive control CreateService did not succeed: {svc}"

    access_key_id, secret_access_key, user_arn = _create_ecs_only_user(ctx)
    _wait_creds_ready(ctx, access_key_id, secret_access_key)
    restricted_ecs = _client_with_creds(ctx, "ecs", access_key_id, secret_access_key)

    nonexistent_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-nonexistent-role-')}"
    bad_family = ctx.unique_name("sim2real-ecs-bad-")

    def _attempt():
        restricted_ecs.register_task_definition(
            family=bad_family,
            requiresCompatibilities=["FARGATE"],
            networkMode="awsvpc",
            cpu="256",
            memory="512",
            executionRoleArn=nonexistent_role_arn,
            containerDefinitions=[{"name": "app", "image": _IMAGE, "essential": True}],
        )

    code, message = _error(_attempt)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    expected = (
        f"User: {user_arn} is not authorized to perform: iam:PassRole on resource: "
        f"{nonexistent_role_arn} because no identity-based policy allows the iam:PassRole action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    families = ctx.client("ecs").list_task_definition_families(familyPrefix=bad_family)["families"]
    assert families == [], f"a task definition family was registered despite the denied PassRole: {families}"

    services = ctx.client("ecs").list_services(cluster=cluster)["serviceArns"]
    assert len(services) == 1, f"expected only the positive-control service to exist, found: {services}"




def _retire_task_def(ecs, arn: str) -> None:
    """Deregister, then delete, one task definition revision, so no INACTIVE revision lingers."""
    ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures") or []
    if failures:
        raise AssertionError(f"DeleteTaskDefinitions refused {arn}: {failures!r}")


def _error(fn) -> tuple[str, str]:
    """The captured AWS error code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected AccessDeniedException, but the call SUCCEEDED and returned {result!r}")


def _default_network(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to create a Fargate service in")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "map-public-ip-on-launch", "Values": ["true"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if not subnets:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to create a Fargate service in")
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecs-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda r=role_name: _delete_role(ctx, r))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
    _wait_role_visible(ctx, role_name)
    return role_arn


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=_EXEC_POLICY_ARN)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _wait_role_visible(ctx, role_name: str, timeout_s: float = 30.0) -> None:
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except Exception:
            time.sleep(2.0)
    raise AssertionError(f"role {role_name} never became visible via GetRole")


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-ecs-cluster-")
    ecs.create_cluster(clusterName=name)
    ctx.on_cleanup(lambda c=name: _delete_cluster_quietly(ctx, c))
    return name


def _delete_cluster_quietly(ctx, cluster: str) -> None:
    ecs = ctx.client("ecs")
    _drain_and_delete_ecs_cluster(ecs, cluster)


def _create_ecs_only_user(ctx) -> tuple[str, str, str]:
    """An IAM user granted broad ecs:* but NO iam:PassRole (default-denied)."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-ecs-nopassrole-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda u=user_name: _delete_user(ctx, u))
    policy_name = "ecs-only-no-passrole"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ecs:RegisterTaskDefinition",
                    "ecs:DeregisterTaskDefinition",
                    "ecs:DescribeTaskDefinition",
                    "ecs:ListTaskDefinitionFamilies",
                    "ecs:ListTaskDefinitions",
                    "ecs:CreateService",
                    "ecs:DescribeServices",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_user_policy(UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    return key["AccessKeyId"], key["SecretAccessKey"], user_arn


def _delete_user(ctx, user_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for key in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for policy_name in iam.list_user_policies(UserName=user_name)["PolicyNames"]:
            iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_user(UserName=user_name)


def _client_with_creds(ctx, service: str, access_key_id: str, secret_access_key: str):
    return ctx.client(
        service,
        creds={"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key},
    )


def _wait_creds_ready(ctx, access_key_id: str, secret_access_key: str, timeout_s: float = 45.0) -> None:
    sts = _client_with_creds(ctx, "sts", access_key_id, secret_access_key)
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            sts.get_caller_identity()
            return
        except Exception as exc:  # eventual consistency of a freshly-created access key
            last_exc = exc
            time.sleep(3.0)
    raise AssertionError(f"new IAM user credentials never became usable: {last_exc}")



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
            except ClientError:
                pass
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
