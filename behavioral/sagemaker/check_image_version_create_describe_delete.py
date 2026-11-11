"""image-version-create-describe-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-version-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateImage then CreateImageVersion is describable once both are CREATED; deleting both
    leaves Describe* ResourceNotFound, and a repeat delete no-ops or reports ResourceNotFound."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    ecr = ctx.client("ecr")
    account_id = sts.get_caller_identity()["Account"]
    role_arn = _create_sagemaker_role(ctx)
    image_name = ctx.unique_name("sim2real-sm-image-")
    repo_name = _create_ecr_repository(ctx, ecr)
    _push_scratch_image(ecr, repo_name, "latest")
    base_image = f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/{repo_name}:latest"

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_image(ImageName=image_name)))
    image_desc = _create_image_until_created(sm, image_name, role_arn)
    assert image_desc["ImageStatus"] == "CREATED", (
        f"expected ImageStatus CREATED, got {image_desc['ImageStatus']!r}"
    )

    ctx.on_cleanup(
        lambda: _safe(lambda: sm.delete_image_version(ImageName=image_name, Version=1))
    )
    sm.create_image_version(ImageName=image_name, BaseImage=base_image, ClientToken=_token())

    version_desc = _poll_until(
        lambda: sm.describe_image_version(ImageName=image_name, Version=1),
        lambda r: r["ImageVersionStatus"] == "CREATED",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert version_desc["ImageVersionStatus"] == "CREATED", (
        f"expected ImageVersionStatus CREATED, got {version_desc['ImageVersionStatus']!r}"
    )
    assert version_desc["ImageArn"] == image_desc["ImageArn"], (
        f"expected ImageArn {image_desc['ImageArn']!r}, got {version_desc.get('ImageArn')!r}"
    )
    assert version_desc["BaseImage"] == base_image, (
        f"expected BaseImage {base_image!r}, got {version_desc.get('BaseImage')!r}"
    )
    assert version_desc["Version"] == 1, f"expected Version 1, got {version_desc.get('Version')!r}"

    image_version_arn = version_desc["ImageVersionArn"]
    sm.delete_image_version(ImageName=image_name, Version=1)
    code, message = _poll_until_gone(
        lambda: sm.describe_image_version(ImageName=image_name, Version=1)
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected_version_message = (
        f"ImageVersion with ARN {image_version_arn} does not exist"
    )
    assert message == expected_version_message, (
        f"expected message {expected_version_message!r}, got {message!r}"
    )
    # A repeat DeleteImageVersion on a deleted version either no-ops or raises ResourceNotFound;
    # AWS is not consistent between the two.
    try:
        sm.delete_image_version(ImageName=image_name, Version=1)
    except ClientError as e:
        repeat = (e.response["Error"]["Code"], e.response["Error"].get("Message"))
        expected_repeat_version = ("ResourceNotFound", f"ImageVersion with ARN {image_version_arn} does not exist")
        assert repeat == expected_repeat_version, (
            f"expected repeat DeleteImageVersion to no-op or report {expected_repeat_version!r}, "
            f"got {repeat!r}"
        )

    sm.delete_image(ImageName=image_name)
    code, message = _poll_until_gone(lambda: sm.describe_image(ImageName=image_name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected_image_message = f"Image with ARN {image_desc['ImageArn']} does not exist"
    assert message == expected_image_message, (
        f"expected message {expected_image_message!r}, got {message!r}"
    )
    try:
        sm.delete_image(ImageName=image_name)
    except ClientError as e:
        repeat = (e.response["Error"]["Code"], e.response["Error"].get("Message"))
        expected_repeat_image = ("ResourceNotFound", f"Image with ARN {image_desc['ImageArn']} does not exist")
        assert repeat == expected_repeat_image, (
            f"expected repeat DeleteImage to no-op or report {expected_repeat_image!r}, got {repeat!r}"
        )




def _token() -> str:
    import uuid

    return uuid.uuid4().hex


_GONE = ("ResourceNotFound", "NoSuchEntity", "RepositoryNotFoundException")


def _safe(fn, deadline_s: float = 60.0) -> None:
    """Delete call: returns once the resource is gone, retries ResourceInUse while a dependent
    delete settles, and raises any other failure."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in _GONE:
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _poll_until_gone(probe, *, timeout_s=60.0, interval_s=3.0):
    """Poll until Describe reports ResourceNotFound: DeleteImageVersion/DeleteImage take effect
    asynchronously, so an immediate Describe can still return the resource."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            probe()
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code == "ResourceNotFound":
                return last_code, e.response["Error"].get("Message")
            raise
        time.sleep(interval_s)
    raise AssertionError(f"resource still present after {timeout_s}s (last code: {last_code!r})")


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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_sagemaker_trust_policy(),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _safe(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_ecr_repository(ctx, ecr) -> str:
    repo_name = ctx.unique_name("sim2real-sm-base-")
    ecr.create_repository(
        repositoryName=repo_name,
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: _safe(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    )
    return repo_name


def _push_scratch_image(ecr, repo_name: str, tag: str) -> None:
    """Push a minimal Docker v2 manifest via the ECR blob-upload API: CreateImageVersion requires
    BaseImage's repository and tag to resolve to a real manifest."""
    import gzip
    import hashlib
    import io

    tar_bytes = b"\x00" * 1024  # minimal valid empty tar archive (two end-of-archive blocks)
    diff_id = hashlib.sha256(tar_bytes).hexdigest()
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    layer_bytes = buf.getvalue()
    layer_digest = hashlib.sha256(layer_bytes).hexdigest()

    config_bytes = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": [f"sha256:{diff_id}"]},
        }
    ).encode()
    config_digest = hashlib.sha256(config_bytes).hexdigest()

    _upload_blob(ecr, repo_name, config_bytes, config_digest)
    _upload_blob(ecr, repo_name, layer_bytes, layer_digest)

    manifest_bytes = json.dumps(
        {
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
    ).encode()
    ecr.put_image(
        repositoryName=repo_name,
        imageManifest=manifest_bytes.decode(),
        imageTag=tag,
    )


def _upload_blob(ecr, repo_name: str, blob: bytes, digest_hex: str) -> None:
    upload = ecr.initiate_layer_upload(repositoryName=repo_name)
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload["uploadId"],
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name,
        uploadId=upload["uploadId"],
        layerDigests=[f"sha256:{digest_hex}"],
    )


def _create_image_until_created(sm, image_name: str, role_arn: str, timeout_s: float = 150.0):
    """Retry create-then-observe while the image lands in CREATE_FAILED with "Unable to assume role"
    (the new role is still propagating); any other terminal failure is raised."""
    deadline = time.monotonic() + timeout_s
    while True:
        _retry_role_propagation(
            lambda: sm.create_image(
                ImageName=image_name,
                RoleArn=role_arn,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
        )
        remaining = max(10.0, deadline - time.monotonic())
        desc = _poll_until(
            lambda: sm.describe_image(ImageName=image_name),
            lambda r: r["ImageStatus"] in ("CREATED", "CREATE_FAILED"),
            timeout_s=remaining,
            interval_s=3.0,
        )
        if desc["ImageStatus"] == "CREATED":
            return desc
        reason = desc.get("FailureReason", "")
        if "role" not in reason.lower() or time.monotonic() >= deadline:
            raise AssertionError(f"CreateImage reached CREATE_FAILED: {reason!r}")
        _safe(lambda: sm.delete_image(ImageName=image_name))
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
