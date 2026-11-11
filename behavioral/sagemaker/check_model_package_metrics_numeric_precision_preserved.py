"""model-package-metrics-numeric-precision-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "model-package-metrics-numeric-precision-preserved"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModelMetrics on CreateModelPackage read back from DescribeModelPackage with the exact
    ContentDigest, S3Uri and ContentType, and BatchDescribeModelPackage reports the same ARN and
    description with no error entry.
    """
    sm = ctx.client("sagemaker")
    image = _push_check_image(ctx)[0]
    group_name = ctx.unique_name("sim2real-mp-metrics-grp-")
    bucket = ctx.unique_name("sim2real-mp-metrics-out-")
    digest = "sha256:" + "".join(f"{i % 16:x}" for i in range(64))
    s3_uri = f"s3://{bucket}/quality/statistics.json"
    description = "sim2real precision-check model package"

    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    resp = sm.create_model_package(
        ModelPackageGroupName=group_name,
        ModelPackageDescription=description,
        ModelApprovalStatus="PendingManualApproval",
        InferenceSpecification={
            "Containers": [
                {"Image": image}
            ],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
        },
        ModelMetrics={
            "ModelQuality": {
                "Statistics": {
                    "ContentType": "application/json",
                    "S3Uri": s3_uri,
                    "ContentDigest": digest,
                }
            }
        },
    )
    package_arn = resp["ModelPackageArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=package_arn))
    # A versioned model package (ModelPackageGroupName set) supports Tags on neither
    # CreateModelPackage nor AddTags -- real AWS: "Tag operations are supported only on ModelPackage
    # Group not on ModelPackage Versions." The version itself cannot carry one.

    described = sm.describe_model_package(ModelPackageName=package_arn)
    statistics = described["ModelMetrics"]["ModelQuality"]["Statistics"]
    assert statistics["ContentDigest"] == digest, (
        f"content digest corrupted: wrote {digest!r}, read back {statistics['ContentDigest']!r}"
    )
    assert statistics["S3Uri"] == s3_uri, (
        f"S3Uri corrupted: wrote {s3_uri!r}, read back {statistics['S3Uri']!r}"
    )
    assert statistics["ContentType"] == "application/json", (
        f"ContentType corrupted: wrote 'application/json', read back {statistics['ContentType']!r}"
    )

    batch = sm.batch_describe_model_package(ModelPackageArnList=[package_arn])
    assert not batch.get("BatchDescribeModelPackageErrorMap"), batch["BatchDescribeModelPackageErrorMap"]
    summary = batch["ModelPackageSummaries"][package_arn]
    assert summary["ModelPackageArn"] == described["ModelPackageArn"], (
        f"BatchDescribeModelPackage ARN {summary['ModelPackageArn']!r} diverges from "
        f"DescribeModelPackage ARN {described['ModelPackageArn']!r} for the same package"
    )
    assert summary["ModelPackageDescription"] == description, (
        f"BatchDescribeModelPackage description corrupted: wrote {description!r}, "
        f"read back {summary['ModelPackageDescription']!r}"
    )


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
