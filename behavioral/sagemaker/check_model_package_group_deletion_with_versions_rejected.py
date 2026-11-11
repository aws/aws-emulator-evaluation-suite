"""model-package-group-deletion-with-versions-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-package-group-deletion-with-versions-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteModelPackageGroup on a group holding a version is rejected with ValidationException
    (not the modeled ConflictException) naming the group and reason; the group survives, and once
    the version is removed the same delete succeeds (positive control)."""
    sm = ctx.client("sagemaker")
    image = _push_check_image(ctx)[0]

    group_name = ctx.unique_name("sim2real-mpg-conflict-")
    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: _cleanup_best_effort(sm, group_name))

    pkg_arn = sm.create_model_package(
        ModelPackageGroupName=group_name,
        ModelApprovalStatus="PendingManualApproval",
        InferenceSpecification={
            "Containers": [
                {"Image": image}
            ],
            "SupportedContentTypes": ["application/json"],
            "SupportedResponseMIMETypes": ["application/json"],
            "SupportedRealtimeInferenceInstanceTypes": ["ml.m5.large"],
        },
    )["ModelPackageArn"]

    code, message = _error(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))
    assert code == "ValidationException", f"expected ValidationException, got {code!r} ({message!r})"
    expected_message = (
        f"Model Package Group {group_arn} cannot be deleted because it still contains "
        "Model Packages."
    )
    assert message == expected_message, (
        f"expected the refusal to name the group and the live-versions reason: "
        f"{expected_message!r}, got {message!r}"
    )

    # Effect absent: the group must still exist.
    described = sm.describe_model_package_group(ModelPackageGroupName=group_name)
    assert described["ModelPackageGroupName"] == group_name, (
        f"expected group {group_name!r} to survive the rejected delete, "
        f"got {described.get('ModelPackageGroupName')!r}"
    )

    # Positive control: remove the blocking version, then deletion succeeds.
    sm.delete_model_package(ModelPackageName=pkg_arn)
    sm.delete_model_package_group(ModelPackageGroupName=group_name)

    final_code, final_message = _poll_until_not_found(sm, group_name, timeout_s=30.0)
    assert final_code == "ValidationException", f"expected ValidationException, got {final_code!r}"
    expected_message = f"ModelPackageGroup {group_arn} does not exist."
    assert final_message == expected_message, (
        f"expected message {expected_message!r}, got {final_message!r}"
    )


def _cleanup_best_effort(sm, group_name: str) -> None:
    summaries = []

    def _list() -> None:
        summaries.extend(sm.list_model_packages(ModelPackageGroupName=group_name).get("ModelPackageSummaryList", []))

    _delete_if_present(_list)
    for summary in summaries:
        _delete_if_present(lambda arn=summary["ModelPackageArn"]: sm.delete_model_package(ModelPackageName=arn))
    _delete_if_present(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))


def _delete_if_present(fn) -> None:
    """Teardown delete: returns once SageMaker reports the resource does not exist, retries the
    'still contains Model Packages' refusal while a package delete settles, and raises the rest."""
    deadline = time.monotonic() + 30
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "")
            gone = err["Code"] == "ResourceNotFound" or (
                err["Code"] == "ValidationException" and "does not exist" in message
            )
            if gone:
                return
            if "still contains" not in message or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises,
    because accepting a call AWS refuses is a failure, not a message mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until_not_found(sm, group_name: str, timeout_s: float = 30.0, interval_s: float = 2.0):
    """Poll DescribeModelPackageGroup until it is refused, returning (code, message); a group
    still describable at the deadline fails loudly."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_model_package_group(ModelPackageGroupName=group_name)
        except ClientError as exc:
            return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"group {group_name!r} still describable after {timeout_s}s")
        time.sleep(interval_s)


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
