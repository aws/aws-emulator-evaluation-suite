"""create-model-package-duplicate-name-version-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-model-package-duplicate-name-version-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModelPackage with a ModelPackageName that already exists fails with ValidationException and
    the exact message and leaves the original package unchanged, while a new name gets its own ARN."""
    sm = ctx.client("sagemaker")
    image = _push_check_image(ctx)[0]

    inference_spec = {
        "Containers": [
            {"Image": image}
        ],
        "SupportedContentTypes": ["text/csv"],
        "SupportedResponseMIMETypes": ["text/csv"],
        "SupportedRealtimeInferenceInstanceTypes": ["ml.m5.large"],
        "SupportedTransformInstanceTypes": ["ml.m5.large"],
    }

    package_name = ctx.unique_name("sim2real-mp-")
    first = sm.create_model_package(ModelPackageName=package_name, InferenceSpecification=inference_spec)
    ctx.on_cleanup(lambda: _delete_model_package_when_settled(sm, package_name))

    # --- negative: same ModelPackageName again ---
    code, message = _error_code_and_message(
        lambda: sm.create_model_package(ModelPackageName=package_name, InferenceSpecification=inference_spec)
    )
    assert code == "ValidationException", f"{code}:{message}"
    expected_message = f"ModelPackage already exists: {first['ModelPackageArn']}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the original package is untouched (still the first one's ARN)
    desc = sm.describe_model_package(ModelPackageName=package_name)
    assert desc["ModelPackageArn"] == first["ModelPackageArn"], (
        f"rejected duplicate create mutated the original package: "
        f"expected ARN {first['ModelPackageArn']!r}, describe returned {desc['ModelPackageArn']!r}"
    )

    # --- positive control: a distinctly named package succeeds ---
    other_name = ctx.unique_name("sim2real-mp-other-")
    second = sm.create_model_package(ModelPackageName=other_name, InferenceSpecification=inference_spec)
    ctx.on_cleanup(lambda: _delete_model_package_when_settled(sm, other_name))
    assert second["ModelPackageArn"] != first["ModelPackageArn"], (
        f"a distinctly named package must get its own ARN, but {other_name!r} returned "
        f"the same ARN as {package_name!r}: {second['ModelPackageArn']!r}"
    )


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_model_package_when_settled(sm, name, timeout_s=120.0, interval_s=3.0):
    """DeleteModelPackage is refused while the package is still InProgress, so wait for
    it to settle first."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = sm.describe_model_package(ModelPackageName=name)["ModelPackageStatus"]
        if status not in ("Pending", "InProgress") or time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    sm.delete_model_package(ModelPackageName=name)


def _push_check_image(ctx, tags=("v1",)) -> list[str]:
    """Push a minimal image to a check-owned ECR repository under each tag; return the image URIs.
    SageMaker resolves the image at create time, so it must exist; no inference is served from it."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-sm-repo-").lower()
    repo_uri = ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["repository"]["repositoryUri"]
    ctx.on_cleanup(lambda: _delete_check_repository(ecr, repo_name))
    for tag in tags:
        _push_minimal_image(ecr, repo_name, tag)
    return [f"{repo_uri}:{tag}" for tag in tags]


def _delete_check_repository(ecr, repo_name) -> None:
    """Force-delete the repository; RepositoryNotFoundException means already gone, the rest raises."""
    from botocore.exceptions import ClientError

    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _push_minimal_image(ecr, repo_name, tag):
    """Push a minimal empty-layer Docker v2 image via the ECR API, without a Docker daemon."""
    import json
    from botocore.exceptions import ClientError
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
