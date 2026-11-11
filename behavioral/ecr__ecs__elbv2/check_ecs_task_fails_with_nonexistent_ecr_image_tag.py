"""ecs-task-fails-with-nonexistent-ecr-image-tag."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time
from typing import Any

from behavioral_harness import tags

CHECK = "ecs-task-fails-with-nonexistent-ecr-image-tag"
GROUP = "permission-boundary"
SERVICES = ["ecr", "ecs", "elbv2"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A task whose image tag does not exist in a pullable ECR repository stops TaskFailedToStart
    with CannotPullContainerError, while a task on an existing tag of the same repository with
    the same role hits no pull error."""
    ecr = ctx.client("ecr")
    subnet_id, sg_id = _default_network(ctx)

    repo_name = ctx.unique_name("sim2real-ecrtag-")
    repo = ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    _push_minimal_image(ecr, repo_name, "v1")

    role_arn = _create_execution_role(ctx)
    cluster = _create_cluster(ctx)

    bad_task_def = _register_taskdef(
        ctx, f"{repo['repositoryUri']}:does-not-exist-tag", role_arn
    )
    ok_task_def = _register_taskdef(ctx, f"{repo['repositoryUri']}:v1", role_arn)

    bad_task = _run_and_wait(ctx, cluster, bad_task_def, subnet_id, sg_id)
    assert bad_task.get("stopCode") == "TaskFailedToStart", (
        f"expected stopCode TaskFailedToStart, got {bad_task.get('stopCode')!r}"
    )
    bad_reason = _failure_text(bad_task)
    assert "CannotPullContainerError" in bad_reason, (
        f"expected a pull error for the nonexistent tag, got {bad_reason!r}"
    )

    ok_task = _run_and_wait(ctx, cluster, ok_task_def, subnet_id, sg_id)
    ok_reason = _failure_text(ok_task)
    assert "CannotPullContainerError" not in ok_reason, (
        f"positive control (existing tag) unexpectedly hit a pull error: {ok_reason!r}"
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
    return role_arn


def _create_cluster(ctx) -> str:
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-cluster-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": CHECK}])
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
        tags=[{"key": "sim2real", "value": CHECK}],
    )["taskDefinition"]
    task_def_arn = reg["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))
    return task_def_arn


def _run_and_wait(
    ctx, cluster: str, task_def_arn: str, subnet_id: str, sg_id: str, timeout_s: float = 240.0
) -> dict[str, Any]:
    ecs = ctx.client("ecs")
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": [subnet_id],
            "securityGroups": [sg_id],
            "assignPublicIp": "ENABLED",
        }
    }
    resp = _run_task_with_retry(ecs, cluster, task_def_arn, net_cfg)
    task_arn = resp["tasks"][0]["taskArn"]
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0]
        if last["lastStatus"] == "STOPPED":
            return last
        time.sleep(5)
    raise AssertionError(f"task did not reach STOPPED within {timeout_s}s, last={last}")


def _run_task_with_retry(
    ecs, cluster: str, task_def_arn: str, net_cfg: dict, timeout_s: float = 90.0, interval_s: float = 5.0
) -> dict[str, Any]:
    """RunTask synchronously calls sts:AssumeRole on the execution role before it will launch
    a task. A role that was JUST created (and just had a policy attached) is often not yet
    visible to that synchronous check -- IAM trust/policy propagation lags role creation. Retry
    on that specific ClientException instead of treating it as a hard failure."""
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = ecs.run_task(
                cluster=cluster,
                taskDefinition=task_def_arn,
                launchType="FARGATE",
                count=1,
                networkConfiguration=net_cfg,
            )
        except Exception as e:  # noqa: BLE001 - inspect message, then re-raise if unrelated
            if "unable to assume the role" in str(e).lower():
                last_err = e
                time.sleep(interval_s)
                continue
            raise
        if resp.get("failures"):
            last_err = AssertionError(f"RunTask reported failures: {resp['failures']}")
            time.sleep(interval_s)
            continue
        return resp
    raise AssertionError(f"RunTask never succeeded within {timeout_s}s (last error: {last_err})")


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
