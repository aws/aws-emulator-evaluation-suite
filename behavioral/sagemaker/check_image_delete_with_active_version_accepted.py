"""image-delete-with-active-version-accepted."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "image-delete-with-active-version-accepted"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteImage with a live ImageVersion succeeds and cascades: DescribeImage and
    DescribeImageVersion settle at ResourceNotFound, and deleting either dead id again fails
    ResourceNotFound.

    Reference: https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DeleteImage.html"""
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    role_arn = _create_execution_role(ctx, iam)
    account_id = sts.get_caller_identity()["Account"]

    # CreateImageVersion resolves BaseImage against ECR, so push a minimal real image.
    repo_name = ctx.unique_name("sim2real-sm-image-repo")
    ecr.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    _push_minimal_image(ecr, repo_name, "latest")
    base_image = f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/{repo_name}:latest"

    image_name = ctx.unique_name("sim2real-sm-image-neg-")
    ctx.on_cleanup(lambda: _delete_image_if_present(ctx, image_name))

    def _create_image():
        return sm.create_image(
            ImageName=image_name,
            RoleArn=role_arn,
            Tags=[{"Key": "sim2real", "Value": "true"}],
        )

    image_arn = _create_image_until_role_usable(sm, image_name, _create_image)["ImageArn"]

    sm.create_image_version(
        ImageName=image_name, BaseImage=base_image, ClientToken=ctx.unique_name("iv-token-")
    )
    version_state = _poll_until_terminal(
        lambda: sm.describe_image_version(ImageName=image_name),
        status_key="ImageVersionStatus",
        success="CREATED",
        failure="CREATE_FAILED",
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert version_state["ImageVersionStatus"] == "CREATED", (
        f"expected the image version to reach CREATED, got "
        f"{version_state['ImageVersionStatus']!r} ({version_state.get('FailureReason')!r})"
    )

    sm.delete_image(ImageName=image_name)

    # The delete is asynchronous (the image passes through DELETING), so poll.
    gone_image_code, gone_image_message = _poll_until_gone(lambda: sm.describe_image(ImageName=image_name))
    assert gone_image_code == "ResourceNotFound", f"expected DescribeImage on the cascade-deleted image to settle at ResourceNotFound, got {gone_image_code!r}"
    assert gone_image_message == f"Image with ARN {image_arn} does not exist", f"unexpected DescribeImage message: {gone_image_message!r}"
    gone_version_code, gone_version_message = _poll_until_gone(lambda: sm.describe_image_version(ImageName=image_name, Version=1))
    assert gone_version_code == "ResourceNotFound", f"expected DescribeImageVersion on the cascade-deleted version to settle at ResourceNotFound, got {gone_version_code!r}"
    assert gone_version_message == f"Image with ARN {image_arn} does not exist", f"unexpected DescribeImageVersion message: {gone_version_message!r}"

    dead_image_delete_code, dead_image_delete_message = _error_code(lambda: sm.delete_image(ImageName=image_name))
    assert dead_image_delete_code == "ResourceNotFound", f"expected a second DeleteImage on the already-deleted image to return ResourceNotFound, got {dead_image_delete_code!r}"
    assert dead_image_delete_message == f"Image with ARN {image_arn} does not exist", f"unexpected second DeleteImage message: {dead_image_delete_message!r}"
    dead_version_delete_code, dead_version_delete_message = _error_code(lambda: sm.delete_image_version(ImageName=image_name, Version=1))
    assert dead_version_delete_code == "ResourceNotFound", f"expected DeleteImageVersion on the already cascade-deleted version to return ResourceNotFound, got {dead_version_delete_code!r}"
    assert dead_version_delete_message == f"Image with ARN {image_arn} does not exist", f"unexpected DeleteImageVersion message: {dead_version_delete_message!r}"


def _delete_image_if_present(ctx, image_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_image_version(ImageName=image_name, Version=1)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    try:
        sm.delete_image(ImageName=image_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error_code(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _poll_until_gone(fn, *, timeout_s=90.0, interval_s=3.0):
    """Poll fn() until it raises a ClientError; return its code and message."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"resource did not become not-found within {timeout_s}s (last value: {last!r})")


def _poll_until_terminal(probe, *, status_key, success, failure, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last[status_key] in (success, failure):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{status_key} did not reach a terminal state within {timeout_s}s (last value: {last!r})"
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
        from botocore.exceptions import ClientError

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


def _create_image_until_role_usable(
    sm, image_name, create_image, *, max_attempts=4, poll_timeout_s=90.0, interval_s=3.0, backoff_s=15.0
):
    """Create the image, retrying delete-and-recreate while it lands CREATE_FAILED with
    'Unable to assume role' during IAM propagation of the new role's trust policy."""
    last_failure_reason = None
    for attempt in range(1, max_attempts + 1):
        _retry_role_propagation(create_image)
        deadline = time.monotonic() + poll_timeout_s
        state = sm.describe_image(ImageName=image_name)
        while state["ImageStatus"] not in ("CREATED", "CREATE_FAILED"):
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"image did not reach a terminal state within {poll_timeout_s}s "
                    f"(last value: {state!r})"
                )
            time.sleep(interval_s)
            state = sm.describe_image(ImageName=image_name)
        if state["ImageStatus"] == "CREATED":
            return state
        last_failure_reason = state.get("FailureReason")
        sm.delete_image(ImageName=image_name)
        if attempt < max_attempts:
            time.sleep(backoff_s)
    raise AssertionError(
        f"image never reached CREATED after {max_attempts} attempts due to IAM role "
        f"trust-policy propagation; last failure was {last_failure_reason!r}"
    )


def _create_execution_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]

    # The role assumed for CreateImage/CreateImageVersion still needs ECR read permissions of
    # its own to pull the BaseImage -- the trust policy alone only lets SageMaker assume it.
    ecr_policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ecr_policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=ecr_policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("role propagation retry loop exited without a result")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
