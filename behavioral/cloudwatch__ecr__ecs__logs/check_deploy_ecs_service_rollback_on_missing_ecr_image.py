"""deploy-ecs-service-rollback-on-missing-ecr-image."""

from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecs-service-rollback-on-missing-ecr-image"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "ecr", "ecs", "logs"]


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An ECS service whose image tag was never pushed to its ECR repository records
    CannotPullContainerError on a stopped task and keeps runningCount 0."""
    ecs = ctx.client("ecs")
    ecr = ctx.client("ecr")
    net = _get_network(ctx)

    cluster_name = ecs.create_cluster(
        clusterName=_xname(ctx, "cluster"), tags=_ecs_tags_kv()
    )["cluster"]["clusterName"]
    ctx.on_cleanup(lambda: _delete_cluster_when_free(ecs, cluster_name))

    repo_name = _xname(ctx, "repo")
    repo = ecr.create_repository(repositoryName=repo_name, tags=_xsvc_tags_kv())[
        "repository"
    ]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    # Never push anything to this repository: the "missing-tag" reference below can never
    # resolve, which is the point.
    missing_image = f"{repo['repositoryUri']}:does-not-exist"

    role = _create_execution_role(ctx)

    net_config = {
        "awsvpcConfiguration": {
            "subnets": [net["subnet_id"]],
            "securityGroups": [net["sg_id"]],
            "assignPublicIp": "ENABLED",
        }
    }

    neg_service = _create_service(
        ctx, ecs, cluster_name, role["arn"], missing_image, net_config, "neg"
    )

    def _neg_running_count() -> int:
        svc = ecs.describe_services(cluster=cluster_name, services=[neg_service])[
            "services"
        ][0]
        return svc["runningCount"]

    def _find_pull_error() -> str:
        tasks = ecs.list_tasks(
            cluster=cluster_name, serviceName=neg_service, desiredStatus="STOPPED"
        ).get("taskArns", [])
        if not tasks:
            return ""
        details = ecs.describe_tasks(cluster=cluster_name, tasks=tasks[:5])["tasks"]
        for t in details:
            for c in t.get("containers", []):
                reason = c.get("reason", "")
                if "CannotPullContainerError" in reason:
                    return reason
            reason = t.get("stoppedReason", "")
            if "CannotPullContainerError" in reason:
                return reason
        return ""

    pull_error = _poll_until(
        _find_pull_error,
        lambda r: "CannotPullContainerError" in r,
        timeout_s=180.0,
        interval_s=10.0,
        description="a stopped task recording CannotPullContainerError",
    )
    assert "CannotPullContainerError" in pull_error, (
        f"expected a stopped task on the missing-image service to record CannotPullContainerError; "
        f"last observed reason: {pull_error!r}"
    )
    neg_running = _neg_running_count()
    assert neg_running == 0, (
        f"expected runningCount 0 for the missing-image service; got {neg_running}"
    )

    pos_service = _create_service(
        ctx,
        ecs,
        cluster_name,
        role["arn"],
        "public.ecr.aws/amazonlinux/amazonlinux:2023",
        net_config,
        "pos",
    )

    def _pos_running_count() -> int:
        svc = ecs.describe_services(cluster=cluster_name, services=[pos_service])[
            "services"
        ][0]
        return svc["runningCount"]

    _poll_until(
        _pos_running_count,
        lambda c: c >= 1,
        timeout_s=240.0,
        interval_s=10.0,
        description="positive-control service running count",
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _ecs_tags_kv() -> list[dict[str, str]]:
    """ECS resource tags use lowercase key/value fields, unlike EC2/CFN's Key/Value."""
    return [{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _get_network(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get(
        "Vpcs", []
    )
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; this check relies on the shared network's "
            "public shared-network subnets for the Fargate service's awsvpc networking and does not "
            "provision a custom VPC/IGW/route-table stack to stay lean"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    ).get("Subnets", [])
    if not subnets:
        raise AssertionError("shared network has no shared-network subnet available")
    subnet_id = subnets[0]["SubnetId"]
    sg = ec2.create_security_group(
        GroupName=_xname(ctx, "sg"),
        Description="sim2real behavioral check SG",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _xsvc_tags_kv()}],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_with_retry(ec2, sg_id))
    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "sg_id": sg_id}


def _delete_sg_with_retry(ec2, sg_id: str, attempts: int = 8) -> None:
    for i in range(attempts):
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as err:
            if (
                err.response["Error"]["Code"] != "DependencyViolation"
                or i == attempts - 1
            ):
                raise
            time.sleep(10.0)


def _create_execution_role(ctx) -> dict[str, str]:
    import json as _json

    iam = ctx.client("iam")
    name = _xname(ctx, "role")
    trust_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_json.dumps(trust_doc)
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return {"name": name, "arn": role["Arn"]}


def _create_service(
    ctx,
    ecs,
    cluster_name: str,
    execution_role_arn: str,
    image: str,
    net_config: dict,
    prefix: str,
) -> str:
    family = _xname(ctx, f"task-{prefix}")
    task_def = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": image,
                "essential": True,
            }
        ],
    )["taskDefinition"]
    task_def_arn = task_def["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    service_name = _xname(ctx, f"svc-{prefix}")
    _create_service_with_role_retry(
        ecs,
        cluster=cluster_name,
        serviceName=service_name,
        taskDefinition=task_def_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration=net_config,
        tags=_ecs_tags_kv(),
    )
    ctx.on_cleanup(
        lambda: ecs.delete_service(
            cluster=cluster_name, service=service_name, force=True
        )
    )
    return service_name


def _create_service_with_role_retry(ecs, timeout_s: float = 60.0, **kwargs):
    """IAM roles are eventually consistent; retry CreateService while ECS reports it still
    can't assume the execution role we just created ("ECS was unable to assume the role...")."""
    deadline = time.monotonic() + timeout_s
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return ecs.create_service(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = str(err)
            last_err = err
            if (
                code in ("ClientException", "InvalidParameterException")
                and "ssume" in msg.lower()
            ):
                time.sleep(5.0)
                continue
            raise
    raise (
        last_err
        if last_err is not None
        else RuntimeError("CreateService never succeeded")
    )


def _delete_cluster_when_free(ecs, cluster, timeout_s=600.0, interval_s=15.0):
    """Delete an ECS cluster, retrying while its capacity providers, tasks or attachments still hold it."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ClusterNotFoundException":
                return
            if code not in ("ClientException", "ClusterContainsTasksException", "UpdateInProgressException",
                            "ClusterContainsServicesException", "ClusterContainsContainerInstancesException") \
                    or time.monotonic() >= deadline:
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
