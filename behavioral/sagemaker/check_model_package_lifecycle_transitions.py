"""model-package-lifecycle-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-package-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModelPackage transitions ModelPackageStatus to Completed, BatchDescribeModelPackage
    reflects that status, and DeleteModelPackage removes the package so a later describe and a
    later mutation on the same dead ARN both hit the same 'does not exist' ValidationException."""
    sm = ctx.client("sagemaker")
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    tag_spec = [{"Key": "sim2real-check", "Value": CHECK}]

    # CreateModelPackage resolves the image manifest at registration time and rejects a
    # registry/repository/tag it cannot pull, so push a minimal real image rather than
    # reference a fabricated account/repo (real AWS: ValidationException "Access denied
    # for registry ID ...").
    repo_name = ctx.unique_name("sim2real-behav-mpg-repo")
    ecr.create_repository(repositoryName=repo_name, tags=tag_spec)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    _push_minimal_image(ecr, repo_name, "latest")
    image = f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/{repo_name}:latest"

    group_name = ctx.unique_name("sim2real-behav-mpg-")
    sm.create_model_package_group(ModelPackageGroupName=group_name, Tags=tag_spec)
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    # A versioned model package (created with ModelPackageGroupName) cannot carry its
    # own Tags -- real AWS: ValidationException "Tags are not supported in Model
    # Package versions. Please add them to the Model Package Group." It inherits the
    # group's tags instead, which is why the group itself is tagged above.
    create_resp = sm.create_model_package(
        ModelPackageGroupName=group_name,
        InferenceSpecification={
            "Containers": [{"Image": image}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
        },
    )
    arn = create_resp["ModelPackageArn"]
    ctx.on_cleanup(lambda: _delete_model_package(sm, arn))

    status = _poll_batch_describe_status(sm, arn, timeout_s=120.0)
    assert status == "Completed", f"expected ModelPackageStatus Completed, got {status}"

    sm.delete_model_package(ModelPackageName=arn)

    # A deleted *versioned* model package does not answer ResourceNotFound: real AWS answers
    # ValidationException with a "does not exist" message. Pin that exact contract, not the
    # ResourceNotFound shape a non-versioned resource would use, and require the ARN in the message
    # so this can't be confused with an unrelated validation failure.
    deadline = time.monotonic() + 30.0
    code, message = None, None
    while time.monotonic() < deadline:
        try:
            sm.describe_model_package(ModelPackageName=arn)
            code, message = None, None  # still visible: deletion not yet propagated
        except ClientError as exc:
            code, message = exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
        if code == "ValidationException" and message and "does not exist" in message:
            break
        time.sleep(1.0)
    else:
        raise AssertionError(f"expected a 'does not exist' ValidationException after delete, got {code}: {message}")

    mutation_code, mutation_message = _error_detail(
        lambda: sm.update_model_package(ModelPackageArn=arn, ModelApprovalStatus="Approved")
    )
    assert mutation_code == "ValidationException" and mutation_message and "does not exist" in mutation_message, (
        f"expected a mutation on the deleted ARN to hit the same 'does not exist' "
        f"ValidationException, got {mutation_code}: {mutation_message}"
    )
    assert mutation_message == f"ModelPackage {create_resp['ModelPackageArn']} does not exist.", (
        f"expected the exact ValidationException message AWS returns, got {mutation_message!r}"
    )


def _error_detail(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _delete_model_package(sm, arn):
    """Teardown: a package SageMaker reports does not exist is gone; any other failure raises."""
    try:
        sm.delete_model_package(ModelPackageName=arn)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ValidationException" and "does not exist" in err.get("Message", "")):
            raise


def _poll_batch_describe_status(sm, arn, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = sm.batch_describe_model_package(ModelPackageArnList=[arn])
        summary = resp.get("ModelPackageSummaries", {}).get(arn)
        if summary is not None:
            status = summary["ModelPackageStatus"]
            if status in ("Completed", "Failed"):
                return status
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for a terminal ModelPackageStatus, last seen {status}")


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
        try:
            ecr.complete_layer_upload(
                repositoryName=repo_name,
                uploadId=upload["uploadId"],
                layerDigests=[f"sha256:{digest}"],
            )
        except ClientError as exc:
            # Identical (e.g. empty) layer content across pushed images/tags can
            # already exist in the repo from an earlier upload in this same check;
            # that's fine, the blob is present either way.
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
