"""ecs-task-fails-when-ecr-repo-policy-denies-pull."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time
from typing import Any

from behavioral_harness import tags

CHECK = "ecs-task-fails-when-ecr-repo-policy-denies-pull"
GROUP = "permission-boundary"
SERVICES = ["ecr", "ecs", "elbv2"]


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A repository policy denying ecr:BatchGetImage/GetDownloadUrlForLayer to the execution role
    makes a Fargate task stop with TaskFailedToStart and CannotPullContainerError; the same task
    pulls without a pull error before the policy is set and after it is deleted."""
    ecr = ctx.client("ecr")
    ctx.client("ecs")
    subnet_id, sg_id = _default_network(ctx)

    repo_name = ctx.unique_name("sim2real-ecrdeny-")
    repo = ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    _push_minimal_image(ecr, repo_name, "v1")
    image_uri = f"{repo['repositoryUri']}:v1"

    role_arn = _create_execution_role(ctx)
    cluster = _create_cluster(ctx)
    task_def_arn = _register_taskdef(ctx, image_uri, role_arn)

    # The pushed image has no ENTRYPOINT/CMD, so the container may still fail to start;
    # only a pull error counts here.
    ok_task = _run_until_pull_settles(ctx, cluster, task_def_arn, subnet_id, sg_id)
    ok_reason = _failure_text(ok_task)
    assert "CannotPullContainerError" not in ok_reason, (
        f"positive control unexpectedly hit a pull error: {ok_reason!r}"
    )

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyExecutionRolePull",
                "Effect": "Deny",
                "Principal": {"AWS": role_arn},
                "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
            }
        ],
    }
    ecr.set_repository_policy(
        repositoryName=repo_name, policyText=json.dumps(deny_policy)
    )

    denied_task = _run_and_wait(ctx, cluster, task_def_arn, subnet_id, sg_id)
    assert denied_task.get("stopCode") == "TaskFailedToStart", (
        f"expected stopCode TaskFailedToStart, got {denied_task.get('stopCode')!r}"
    )
    denied_reason = _failure_text(denied_task)
    assert "CannotPullContainerError" in denied_reason, (
        f"expected a pull error after the deny policy was attached, got {denied_reason!r}"
    )

    ecr.delete_repository_policy(repositoryName=repo_name)
    restored_task = _run_until_pull_settles(ctx, cluster, task_def_arn, subnet_id, sg_id)
    restored_reason = _failure_text(restored_task)
    assert "CannotPullContainerError" not in restored_reason, (
        f"expected the identical RunTask to succeed again after DeleteRepositoryPolicy, "
        f"got {restored_reason!r}"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    )
    # IAM role trust propagation is eventually consistent; _run_until_pull_settles retries for it.
    return role_arn


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])
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
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskDefinition"]
    task_def_arn = reg["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _run_until_pull_settles(
    ctx, cluster: str, task_def_arn: str, subnet_id: str, sg_id: str, window_s: float = 180.0
) -> dict[str, Any]:
    """Run+wait, retrying to a deadline while RunTask fails to assume the role or the task stops
    with a pull error (IAM trust and policy-removal propagation). Not used for the denied run."""
    from botocore.exceptions import ClientError

    left = ctx.time_left()
    deadline = time.monotonic() + (window_s if left is None else min(window_s, left))
    while True:
        try:
            last_task = _run_and_wait(ctx, cluster, task_def_arn, subnet_id, sg_id)
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(2.0)
            continue
        if "CannotPullContainerError" not in _failure_text(last_task) or time.monotonic() >= deadline:
            return last_task
        time.sleep(2.0)


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
