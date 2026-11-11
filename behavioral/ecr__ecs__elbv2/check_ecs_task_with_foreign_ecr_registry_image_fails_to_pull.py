"""ecs-task-with-foreign-ecr-registry-image-fails-to-pull."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time
from typing import Any

from behavioral_harness import tags

CHECK = "ecs-task-with-foreign-ecr-registry-image-fails-to-pull"
GROUP = "permission-boundary"
SERVICES = ["ecr", "ecs", "elbv2"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A task whose image names another account's ECR registry stops TaskFailedToStart with
    CannotPullContainerError, while a task on the caller's own registry with the same execution
    role hits no pull error."""
    ecr = ctx.client("ecr")
    subnet_id, sg_id = _default_network(ctx)

    repo_name = ctx.unique_name("sim2real-ecracct-")
    repo = ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "Name", "Value": repo_name}]
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    _push_minimal_image(ecr, repo_name, "v1")

    role_arn = _create_execution_role(ctx)
    cluster = _create_cluster(ctx)

    # 111122223333 is the AWS documentation example account, never the caller's, so this
    # registry hostname names a repository the caller cannot see.
    foreign_image = (
        f"111122223333.dkr.ecr.{ctx.region}.amazonaws.com/{repo_name}:v1"
    )
    bad_task_def = _register_taskdef(ctx, foreign_image, role_arn)
    ok_task_def = _register_taskdef(ctx, f"{repo['repositoryUri']}:v1", role_arn)

    bad_task = _run_past_role_propagation(ctx, cluster, bad_task_def, subnet_id, sg_id)
    assert bad_task.get("stopCode") == "TaskFailedToStart", (
        f"expected stopCode TaskFailedToStart, got {bad_task.get('stopCode')!r}"
    )
    bad_reason = _failure_text(bad_task)
    assert "CannotPullContainerError" in bad_reason, (
        f"expected a pull error for the foreign-account registry, got {bad_reason!r}"
    )

    ok_task = _run_past_role_propagation(ctx, cluster, ok_task_def, subnet_id, sg_id)
    ok_reason = _failure_text(ok_task)
    assert "CannotPullContainerError" not in ok_reason, (
        f"positive control (own account registry) unexpectedly hit a pull error: {ok_reason!r}"
    )


def _empty_layer_bytes() -> tuple[bytes, str]:
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w"):
        pass
    tar_bytes = tar_buf.getvalue()
    tar_digest = hashlib.sha256(tar_bytes).hexdigest()
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    return gz_buf.getvalue(), tar_digest


def _upload_blob(ecr: Any, repo_name: str, blob: bytes) -> str:
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    avail = ecr.batch_check_layer_availability(
        repositoryName=repo_name, layerDigests=[digest]
    ).get("layers", [])
    if avail and avail[0].get("layerAvailability") == "AVAILABLE":
        return digest
    up = ecr.initiate_layer_upload(repositoryName=repo_name)
    upload_id = up["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


def _push_minimal_image(ecr: Any, repo_name: str, tag: str) -> str:
    layer_bytes, tar_digest = _empty_layer_bytes()
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)
    config_bytes = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": [f"sha256:{tar_digest}"]},
        }
    ).encode()
    config_digest = _upload_blob(ecr, repo_name, config_bytes)
    manifest_json = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": len(config_bytes),
                "digest": config_digest,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "size": len(layer_bytes),
                    "digest": layer_digest,
                }
            ],
        }
    )
    resp = ecr.put_image(
        repositoryName=repo_name,
        imageManifest=manifest_json,
        imageManifestMediaType="application/vnd.docker.distribution.manifest.v2+json",
        imageTag=tag,
    )
    return resp["image"]["imageId"]["imageDigest"]


def _default_network(ctx) -> tuple[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a Fargate task for the pull test")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if not subnets:
        raise AssertionError("shared network has no subnets available for Fargate networking")
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsx-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    )
    return role_arn


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "Name", "value": name}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    return name


def _register_taskdef(ctx, image_uri: str, execution_role_arn: str) -> str:
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-taskdef-")
    reg = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=execution_role_arn,
        containerDefinitions=[{"name": "app", "image": image_uri, "essential": True}],
        tags=[{"key": "Name", "value": family}],
    )["taskDefinition"]
    task_def_arn = reg["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _run_and_wait(
    ctx, cluster: str, task_def_arn: str, subnet_id: str, sg_id: str, timeout_s: float = 240.0
) -> dict[str, Any]:
    ecs = ctx.client("ecs")
    resp = ecs.run_task(
        cluster=cluster,
        taskDefinition=task_def_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [subnet_id],
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
    )
    if resp.get("failures"):
        raise AssertionError(f"run_task failed immediately: {resp['failures']}")
    task_arn = resp["tasks"][0]["taskArn"]
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0]
        if last["lastStatus"] == "STOPPED":
            return last
        time.sleep(5)
    raise AssertionError(f"task did not reach STOPPED within {timeout_s}s, last={last}")


def _run_past_role_propagation(
    ctx, cluster: str, task_def_arn: str, subnet_id: str, sg_id: str, deadline_s: float = 90.0
) -> dict[str, Any]:
    """A freshly created execution role's trust to ecs-tasks.amazonaws.com is eventually
    consistent to STS/ECS (https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency).
    While the trust has not yet propagated, RunTask itself raises
    ClientException("ECS was unable to assume the role ...") synchronously, before a task
    ever exists. Retry past exactly that error, bounded by deadline_s; once RunTask succeeds,
    the resulting task's own outcome (whatever it is) is returned as-is -- a run that reaches
    a real task is no longer a role-propagation question."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return _run_and_wait(ctx, cluster, task_def_arn, subnet_id, sg_id)
        except Exception as e:
            if "unable to assume the role" not in str(e) or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _failure_text(task: dict[str, Any]) -> str:
    parts = [task.get("stoppedReason", "")]
    for c in task.get("containers", []):
        parts.append(c.get("reason", ""))
    return " | ".join(parts)


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
