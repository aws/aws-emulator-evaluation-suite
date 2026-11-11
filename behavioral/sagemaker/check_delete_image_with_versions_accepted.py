"""delete-image-with-versions-accepted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-image-with-versions-accepted"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteImage on an image with a live ImageVersion cascades: image and version both become
    ResourceNotFound (DescribeImage/DescribeImageVersion, absent from ListImages), and a second
    DeleteImage fails ResourceNotFound rather than silently no-opping."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    ecr = ctx.client("ecr")
    role_arn = _create_sagemaker_role(ctx)
    account_id = sts.get_caller_identity()["Account"]
    image_name = ctx.unique_name("sim2real-sm-image-")

    # CreateImageVersion resolves BaseImage against real ECR (repo AND tag must exist),
    # so push a minimal real image rather than pointing at a fabricated URI.
    repo_name = ctx.unique_name("sim2real-sm-repo")
    ecr.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: _safe(lambda: ecr.delete_repository(repositoryName=repo_name, force=True)))
    _push_minimal_image(ecr, repo_name, "latest")
    base_image = f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/{repo_name}:latest"

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_image(ImageName=image_name)))
    _create_image_with_role_retry(sm, image_name, role_arn)

    ctx.on_cleanup(
        lambda: _safe(lambda: sm.delete_image_version(ImageName=image_name, Version=1))
    )
    sm.create_image_version(ImageName=image_name, BaseImage=base_image, ClientToken=_token())
    _poll_until(
        lambda: sm.describe_image_version(ImageName=image_name, Version=1),
        lambda r: r["ImageVersionStatus"] == "CREATED",
        timeout_s=60.0,
        interval_s=3.0,
    )

    # The cascade is asynchronous: image and version pass through a transient deleting
    # window before an independent read reports them gone.
    sm.delete_image(ImageName=image_name)

    image_gone_message = _wait_for_error_code(
        lambda: sm.describe_image(ImageName=image_name),
        "ResourceNotFound",
        what="image after cascading DeleteImage",
    )
    expected_image_gone = f"Image with ARN arn:aws:sagemaker:{ctx.region}:{ctx.account}:image/{image_name} does not exist"
    assert image_gone_message == expected_image_gone, (
        f"expected {expected_image_gone!r}, got {image_gone_message!r}"
    )
    version_gone_message = _wait_for_error_code(
        lambda: sm.describe_image_version(ImageName=image_name, Version=1),
        "ResourceNotFound",
        what="image version after cascading DeleteImage",
    )
    expected_version_gone = f"Image with ARN arn:aws:sagemaker:{ctx.region}:{ctx.account}:image/{image_name} does not exist"
    assert version_gone_message == expected_version_gone, (
        f"expected {expected_version_gone!r}, got {version_gone_message!r}"
    )

    _poll_until(
        lambda: [img["ImageName"] for img in sm.list_images(NameContains=image_name)["Images"]],
        lambda names: image_name not in names,
        timeout_s=30.0,
        interval_s=3.0,
    )

    second_code, second_message = _error_code_and_message(
        lambda: sm.delete_image(ImageName=image_name)
    )
    assert second_code == "ResourceNotFound", (
        f"expected double-delete to fail ResourceNotFound, got {second_code!r}: {second_message!r}"
    )
    expected_second = f"Image with ARN arn:aws:sagemaker:{ctx.region}:{ctx.account}:image/{image_name} does not exist"
    assert second_message == expected_second, (
        f"expected {expected_second!r}, got {second_message!r}"
    )




def _token() -> str:
    import uuid

    return uuid.uuid4().hex


def _safe(fn) -> None:
    """Run a delete; return once the resource is gone, retry ResourceInUse, raise the rest."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFound", "RepositoryNotFoundException", "NoSuchEntity"):
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


def _push_minimal_image(ecr, repo_name, tag):
    """Push a minimal empty-layer Docker v2 image via the ECR API, without a Docker daemon."""
    import gzip
    import hashlib
    import io
    import tarfile

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w"):
        pass
    tar_bytes = tar_buf.getvalue()
    diff_id = hashlib.sha256(tar_bytes).hexdigest()

    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    layer_bytes = gz_buf.getvalue()
    layer_digest = hashlib.sha256(layer_bytes).hexdigest()

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{diff_id}"]},
    }
    config_bytes = json.dumps(config).encode()
    config_digest = hashlib.sha256(config_bytes).hexdigest()

    def _upload_blob(blob: bytes, digest: str) -> None:
        upload = ecr.initiate_layer_upload(repositoryName=repo_name)
        ecr.upload_layer_part(
            repositoryName=repo_name,
            uploadId=upload["uploadId"],
            partFirstByte=0,
            partLastByte=len(blob) - 1,
            layerPartBlob=blob,
        )
        try:
            ecr.complete_layer_upload(
                repositoryName=repo_name,
                uploadId=upload["uploadId"],
                layerDigests=[f"sha256:{digest}"],
            )
        except ClientError as exc:
            # Identical (e.g. empty) layer content may already exist in the repo.
            if exc.response["Error"]["Code"] != "LayerAlreadyExistsException":
                raise

    _upload_blob(layer_bytes, layer_digest)
    _upload_blob(config_bytes, config_digest)

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": f"sha256:{config_digest}",
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_bytes),
                "digest": f"sha256:{layer_digest}",
            }
        ],
    }
    ecr.put_image(
        repositoryName=repo_name,
        imageManifest=json.dumps(manifest),
        imageTag=tag,
    )


def _wait_for_error_code(probe, expected_code, *, what, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            probe()
            last_code = None
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code == expected_code:
                return exc.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(
        f"expected {what} to reach {expected_code!r} within {timeout_s}s, last code was {last_code!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _sagemaker_trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sagemaker.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_sagemaker_trust_policy())
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _safe(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_image_with_role_retry(sm, image_name: str, role_arn: str, timeout_s: float = 180.0, interval_s: float = 5.0):
    """Retry CreateImage until CREATED while IAM propagates the role.

    Role validation fails either synchronously (ValidationException) or as CREATE_FAILED."""
    deadline = time.monotonic() + timeout_s
    last_detail = None
    while time.monotonic() < deadline:
        try:
            sm.create_image(ImageName=image_name, RoleArn=role_arn)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_detail = message
                time.sleep(interval_s)
                continue
            raise
        desc = _poll_until(
            lambda: sm.describe_image(ImageName=image_name),
            lambda r: r["ImageStatus"] in ("CREATED", "CREATE_FAILED"),
            timeout_s=60.0,
            interval_s=3.0,
        )
        if desc["ImageStatus"] == "CREATED":
            return desc
        last_detail = desc.get("FailureReason", "")
        if "assume role" not in last_detail.lower():
            raise AssertionError(f"CreateImage failed for a reason other than role propagation: {last_detail}")
        _safe(lambda: sm.delete_image(ImageName=image_name))
        time.sleep(interval_s)
    raise AssertionError(f"CreateImage did not reach CREATED within {timeout_s}s (last detail: {last_detail})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
