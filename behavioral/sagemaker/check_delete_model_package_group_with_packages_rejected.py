"""delete-model-package-group-with-packages-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-model-package-group-with-packages-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteModelPackageGroup on a group that still contains a ModelPackage version is
    rejected with ValidationException, the group survives the failed delete, and once the
    package is removed the very same delete call succeeds (positive control)."""
    sm = ctx.client("sagemaker")
    ecr = ctx.client("ecr")
    group_name = ctx.unique_name("sim2real-mpg-conflict-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # CreateModelPackage validates that the referenced ECR repository actually exists.
    repo_name = ctx.unique_name("sim2real-mpgc-repo")
    ecr.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    sm.create_model_package_group(ModelPackageGroupName=group_name)
    _push_minimal_image(ecr, repo_name, "tag0")
    image = f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/{repo_name}:tag0"
    pkg_arn = sm.create_model_package(
        ModelPackageGroupName=group_name,
        InferenceSpecification={"Containers": [{"Image": image}]},
        ModelApprovalStatus="PendingManualApproval",
    )["ModelPackageArn"]

    cleanup_done = {"value": False}

    def cleanup():
        if cleanup_done["value"]:
            return
        import time

        from botocore.exceptions import ClientError

        # The group delete is refused with "still contains Model Packages" until the package
        # delete settles: retry that refusal every 2 s for up to 120 s, then raise.
        deadline = time.monotonic() + 120
        for delete in (
            lambda: sm.delete_model_package(ModelPackageName=pkg_arn),
            lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name),
        ):
            while True:
                try:
                    delete()
                    break
                except ClientError as exc:
                    error = exc.response["Error"]
                    message = error.get("Message", "")
                    if error["Code"] == "ValidationException" and "does not exist" in message:
                        break
                    if "still contains" not in message or time.monotonic() >= deadline:
                        raise
                time.sleep(2)

    ctx.on_cleanup(cleanup)

    # Breaking exactly one thing: try to delete a group that still owns a package.
    group_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:model-package-group/{group_name}"
    code, message = _error_code_and_message(
        lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}: {message!r}"
    expected_message = (
        f"Model Package Group {group_arn} cannot be deleted because it still contains "
        "Model Packages."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: the group must still exist after the rejected delete.
    still_there = sm.describe_model_package_group(ModelPackageGroupName=group_name)
    assert still_there["ModelPackageGroupName"] == group_name, (
        f"expected group {group_name!r} to survive the rejected delete, "
        f"got {still_there['ModelPackageGroupName']!r}"
    )

    # Positive control: once the blocking package is gone, the identical delete call succeeds.
    sm.delete_model_package(ModelPackageName=pkg_arn)
    sm.delete_model_package_group(ModelPackageGroupName=group_name)
    cleanup_done["value"] = True

    not_found_code, not_found_message = _error_code_and_message(
        lambda: sm.describe_model_package_group(ModelPackageGroupName=group_name)
    )
    assert not_found_code == "ValidationException", (
        f"expected ValidationException after successful delete, got {not_found_code!r}: "
        f"{not_found_message!r}"
    )
    expected_gone = f"ModelPackageGroup {group_arn} does not exist."
    assert not_found_message == expected_gone, (
        f"expected {expected_gone!r}, got {not_found_message!r}"
    )


# ===== helpers =====
def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _push_minimal_image(ecr, repo_name, tag):
    """Push a minimal (empty-layer) Docker v2 image directly via the ECR API so that
    an ECR-existence-validating SageMaker call (e.g. CreateModelPackage) resolves a
    real image, without needing a Docker daemon."""
    import gzip
    import hashlib
    import io
    import json
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
        ecr.complete_layer_upload(
            repositoryName=repo_name,
            uploadId=upload["uploadId"],
            layerDigests=[f"sha256:{digest}"],
        )

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
