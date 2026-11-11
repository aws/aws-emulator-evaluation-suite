"""ecs-taskdef-image-digest-pinning-matches-ecr."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ecs-taskdef-image-digest-pinning-matches-ecr"
GROUP = "resource-reference"
SERVICES = ["ecr", "ecs", "elbv2"]


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ecsxdig-")
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A task definition pinned to an image by @sha256 digest stores that exact reference, and
    the stored digest matches the one ECR reports via DescribeImages for the pushed manifest --
    the true content digest ECR computed at push time, not a locally-guessed or truncated value.
    """
    ecr = ctx.client("ecr")
    ecs = ctx.client("ecs")

    repo_name = ctx.unique_name("sim2real-ecrdigest-")
    repo = ecr.create_repository(repositoryName=repo_name)["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    digest = _push_minimal_image(ecr, repo_name, "v1")

    described = ecr.describe_images(
        repositoryName=repo_name, imageIds=[{"imageDigest": digest}]
    )["imageDetails"]
    assert len(described) == 1
    assert described[0]["imageDigest"] == digest
    assert "v1" in described[0].get("imageTags", [])

    image_ref = f"{repo['repositoryUri']}@{digest}"
    execution_role_arn = _create_execution_role(ctx)
    family = ctx.unique_name("sim2real-taskdef-")

    # A brand-new role's trust policy can lag briefly before ECS will accept it in
    # RegisterTaskDefinition; retry the registration itself rather than sleeping
    # unconditionally beforehand.
    def _attempt():
        try:
            return ecs.register_task_definition(
                family=family,
                requiresCompatibilities=["FARGATE"],
                networkMode="awsvpc",
                cpu="256",
                memory="512",
                executionRoleArn=execution_role_arn,
                containerDefinitions=[{"name": "app", "image": image_ref, "essential": True}],
            )["taskDefinition"]
        except ClientError as exc:
            return exc

    reg = _poll_until(
        _attempt,
        lambda r: not isinstance(r, ClientError),
        timeout_s=60,
        interval_s=3,
        description="the freshly created execution role to propagate enough for ECS to accept it",
    )
    task_def_arn = reg["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    stored_image = ecs.describe_task_definition(taskDefinition=task_def_arn)[
        "taskDefinition"
    ]["containerDefinitions"][0]["image"]
    assert stored_image == image_ref
    stored_digest = stored_image.rsplit("@", 1)[1]
    assert stored_digest == described[0]["imageDigest"], (
        "task definition digest does not match ecr:DescribeImages digest: "
        f"{stored_digest!r} != {described[0]['imageDigest']!r}"
    )


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


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
    """Pushes a minimal, valid single-layer Docker v2 image to `repo_name:tag` using only
    the ECR control-plane layer-upload/PutImage APIs (no docker daemon required), and
    returns the image digest ECR assigned. The image has no ENTRYPOINT/CMD, so any task
    that runs it will pull successfully but fail to start with a deterministic,
    non-pull-related error -- useful as a shared fixture for pull-boundary checks."""
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
