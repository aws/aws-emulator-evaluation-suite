"""batch-describe-model-package-matches-individual-creates."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-describe-model-package-matches-individual-creates"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDescribeModelPackage entries match DescribeModelPackage for each created package,
    and a nonexistent ARN lands in the per-item error map without poisoning valid entries."""
    sm = ctx.client("sagemaker")
    ecr = ctx.client("ecr")
    group_name = ctx.unique_name("sim2real-bdmp-group-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # CreateModelPackage validates that the referenced ECR repository AND image tag
    # actually exist (it resolves the image manifest), so push a minimal real image.
    repo_name = ctx.unique_name("sim2real-bdmp-repo")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real:check", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    arns = []
    expected = {}
    for i in range(2):
        tag = f"tag{i}"
        _push_minimal_image(ecr, repo_name, tag)
        image = f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/{repo_name}:{tag}"
        description = f"sim2real-behavioral-package-{i}"
        resp = sm.create_model_package(
            ModelPackageGroupName=group_name,
            ModelPackageDescription=description,
            InferenceSpecification={"Containers": [{"Image": image}]},
            ModelApprovalStatus="PendingManualApproval",
        )
        arn = resp["ModelPackageArn"]
        arns.append(arn)
        ctx.on_cleanup(lambda a=arn: sm.delete_model_package(ModelPackageName=a))
        individual = _settled_package(ctx, sm, arn)
        expected[arn] = {
            "ModelPackageGroupName": individual["ModelPackageGroupName"],
            "ModelPackageVersion": individual["ModelPackageVersion"],
            "ModelPackageDescription": individual["ModelPackageDescription"],
            "ModelPackageStatus": individual["ModelPackageStatus"],
            "ModelApprovalStatus": individual["ModelApprovalStatus"],
            "Image": individual["InferenceSpecification"]["Containers"][0]["Image"],
        }

    bogus_arn = (
        f"arn:aws:sagemaker:{ctx.region}:{account_id}:model-package/"
        f"{group_name}/9999"
    )

    batch = sm.batch_describe_model_package(ModelPackageArnList=arns + [bogus_arn])

    summaries = batch["ModelPackageSummaries"]
    for arn in arns:
        assert arn in summaries, f"expected {arn} in ModelPackageSummaries, got keys {list(summaries)}"
        summary = summaries[arn]
        exp = expected[arn]
        assert summary["ModelPackageGroupName"] == exp["ModelPackageGroupName"], (
            f"{arn}: expected ModelPackageGroupName {exp['ModelPackageGroupName']!r}, "
            f"got {summary['ModelPackageGroupName']!r}"
        )
        assert summary["ModelPackageVersion"] == exp["ModelPackageVersion"], (
            f"{arn}: expected ModelPackageVersion {exp['ModelPackageVersion']!r}, "
            f"got {summary['ModelPackageVersion']!r}"
        )
        assert summary["ModelPackageDescription"] == exp["ModelPackageDescription"], (
            f"{arn}: expected ModelPackageDescription {exp['ModelPackageDescription']!r}, "
            f"got {summary['ModelPackageDescription']!r}"
        )
        assert summary["ModelPackageStatus"] == exp["ModelPackageStatus"], (
            f"{arn}: expected ModelPackageStatus {exp['ModelPackageStatus']!r}, "
            f"got {summary['ModelPackageStatus']!r}"
        )
        assert summary["ModelApprovalStatus"] == exp["ModelApprovalStatus"], (
            f"{arn}: expected ModelApprovalStatus {exp['ModelApprovalStatus']!r}, "
            f"got {summary['ModelApprovalStatus']!r}"
        )
        assert summary["InferenceSpecification"]["Containers"][0]["Image"] == exp["Image"], (
            f"{arn}: expected Image {exp['Image']!r}, "
            f"got {summary['InferenceSpecification']['Containers'][0]['Image']!r}"
        )

    error_map = batch["BatchDescribeModelPackageErrorMap"]
    assert bogus_arn in error_map, (
        f"expected the non-existent ARN {bogus_arn} to appear in BatchDescribeModelPackageErrorMap, "
        f"got keys {list(error_map)}"
    )
    bogus_error = error_map[bogus_arn]
    expected = ("EntityNotFoundError", "The ARN is not found.")
    assert (bogus_error["ErrorCode"], bogus_error["ErrorResponse"]) == expected, (
        f"expected ErrorCode and ErrorResponse {expected!r} for a non-existent ARN, got {bogus_error!r}"
    )
    assert bogus_arn not in summaries, "non-existent ARN must not appear in ModelPackageSummaries"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


def _settled_package(ctx, sm, arn):
    """DescribeModelPackage once ModelPackageStatus leaves Pending/InProgress, so a later read of
    the same package reports the same status."""
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else max(1.0, min(120.0, left - 5.0)))
    while True:
        described = sm.describe_model_package(ModelPackageName=arn)
        if described["ModelPackageStatus"] in ("Completed", "Failed", "Deleting"):
            return described
        if time.monotonic() >= deadline:
            left = ctx.time_left()
            if left is not None and left <= 6.0:
                raise TimeoutError("model package settling: the run budget ended first; not graded")
            raise AssertionError(
                f"model package {arn} never settled past {described['ModelPackageStatus']!r}"
            )
        time.sleep(2)


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
            # Identical (e.g. empty) layer content may already exist from an earlier push.
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

