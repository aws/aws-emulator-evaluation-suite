"""create-model-package-malformed-image-uri-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-model-package-malformed-image-uri-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateModelPackage with a malformed container image URI is rejected before being persisted."""
    sm = ctx.client("sagemaker")

    bad_name = ctx.unique_name("sim2real-behav-mp-bad-")
    bad_image = "this_is_not_an_ecr_image_uri"
    code, message = _error_code_and_message(lambda: sm.create_model_package(
        ModelPackageName=bad_name,
        InferenceSpecification={
            "Containers": [{"Image": bad_image}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
            "SupportedRealtimeInferenceInstanceTypes": ["ml.t2.medium"],
            # required for an unversioned (standalone) model package
            "SupportedTransformInstanceTypes": ["ml.m5.large"],
        },
    ))
    assert code == "ValidationException", f"expected ValidationException for image {bad_image!r}, got {code!r}"
    assert message == "Provided image is not a valid ECR image.", (
        f"expected message 'Provided image is not a valid ECR image.', got {message!r}"
    )

    # effect absent: the model package was never persisted
    describe_code, describe_message = _error_code_and_message(
        lambda: sm.describe_model_package(ModelPackageName=bad_name)
    )
    assert describe_code == "ValidationException", (
        f"expected DescribeModelPackage on the never-created {bad_name!r} to fail with "
        f"ValidationException, got {describe_code!r}"
    )
    expected_describe = (
        f"ModelPackage arn:aws:sagemaker:{ctx.region}:{ctx.account}:model-package/{bad_name} does not exist."
    )
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )

    # positive control: a well-formed ECR-style image URI is accepted
    good_name = ctx.unique_name("sim2real-behav-mp-good-")
    image_uri = _push_check_image(ctx)[0]
    resp = sm.create_model_package(
        ModelPackageName=good_name,
        InferenceSpecification={
            "Containers": [{"Image": image_uri}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
            "SupportedRealtimeInferenceInstanceTypes": ["ml.t2.medium"],
            "SupportedTransformInstanceTypes": ["ml.m5.large"],
        },
        Tags=[{"Key": "sim2real", "Value": "create-model-package-malformed-image-uri-rejected"}],
    )
    ctx.on_cleanup(lambda: _delete_model_package_when_settled(sm, good_name))
    assert resp["ModelPackageArn"].endswith(good_name), (
        f"expected ModelPackageArn to end with {good_name!r}, got {resp['ModelPackageArn']!r}"
    )


def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
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
    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _push_minimal_image(ecr, repo_name, tag):
    """Push a minimal empty-layer Docker v2 image via the ECR API, without a Docker daemon."""
    import json
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
