"""sagemaker-model-package-s3-artifact-registry-positive."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
import time
from urllib.parse import urlparse

from behavioral_harness import tags

CHECK = "sagemaker-model-package-s3-artifact-registry-positive"
GROUP = "model-deploy"
SERVICES = ["s3", "sagemaker"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CreateModelPackage with S3 source artifacts registers version 1 of its group, reaches
    Completed, and DescribeModelPackage reports the S3 URL, which resolves via S3 GetObject to
    the exact bytes that were registered."""
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")

    bucket = _create_bucket(ctx, s3, "modelpkg")
    key = "artifacts/model.tar.gz"
    content = b"sim2real model-package artifact bytes: " + os.urandom(64)
    s3.put_object(Bucket=bucket, Key=key, Body=content)
    expected_sha256 = hashlib.sha256(content).hexdigest()

    account_id = sts.get_caller_identity()["Account"]
    # CreateModelPackage validates that the referenced ECR image (repository AND tag) actually
    # exists before it will register the package - push a minimal scratch image (no docker
    # needed: hand-build a valid OCI/Docker v2 manifest + blobs via the raw ECR blob-upload API)
    # so the container reference genuinely resolves.
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-modelpkg-test")
    ecr.create_repository(
        repositoryName=repo_name,
        tags=[{"Key": "sim2real", "Value": "model-package-registry"}],
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    _push_scratch_image(ecr, repo_name, "latest")
    image_uri = f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/{repo_name}:latest"

    group_name = ctx.unique_name("sim2real-sm-mpg-")
    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real", "Value": "model-package-registry"}],
    )
    ctx.on_cleanup(
        lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name)
    )

    model_data_url = f"s3://{bucket}/{key}"
    create_resp = sm.create_model_package(
        ModelPackageGroupName=group_name,
        InferenceSpecification={
            "Containers": [{"Image": image_uri, "ModelDataUrl": model_data_url}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
        },
        ModelApprovalStatus="PendingManualApproval",
    )
    model_package_arn = create_resp["ModelPackageArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=model_package_arn))

    deadline = time.monotonic() + min(300.0, (ctx.time_left() or 300.0) - 5)
    desc = sm.describe_model_package(ModelPackageName=model_package_arn)
    while desc["ModelPackageStatus"] in ("Pending", "InProgress") and time.monotonic() < deadline:
        time.sleep(5)
        desc = sm.describe_model_package(ModelPackageName=model_package_arn)
    derived = (
        desc["ModelPackageStatus"],
        desc.get("ModelPackageVersion"),
        desc.get("ModelPackageGroupName"),
        desc.get("ModelApprovalStatus"),
        desc.get("ModelPackageArn"),
    )
    assert derived == ("Completed", 1, group_name, "PendingManualApproval", model_package_arn), (
        f"expected the first package of {group_name!r} to be Completed version 1, "
        f"PendingManualApproval, at {model_package_arn!r}; got "
        f"(status, version, group, approval, arn)={derived!r}"
    )
    described_url = desc["InferenceSpecification"]["Containers"][0]["ModelDataUrl"]
    assert described_url == model_data_url, (
        f"expected {model_data_url!r}, got {described_url!r}"
    )

    parsed = urlparse(described_url)
    described_bucket = parsed.netloc
    described_key = parsed.path.lstrip("/")
    obj = s3.get_object(Bucket=described_bucket, Key=described_key)
    fetched = obj["Body"].read()
    assert fetched == content, (
        "GetObject on the DescribeModelPackage-reported S3 location did not return the registered artifact bytes"
    )
    fetched_sha256 = hashlib.sha256(fetched).hexdigest()
    assert fetched_sha256 == expected_sha256, (
        f"expected sha256 {expected_sha256!r}, got {fetched_sha256!r}"
    )


def _upload_blob(ecr, repo_name: str, blob: bytes) -> str:
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()
    upload = ecr.initiate_layer_upload(repositoryName=repo_name)
    upload_id = upload["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


def _push_scratch_image(ecr, repo_name: str, tag: str) -> None:
    """Hand-build and push a minimal valid Docker v2 image (empty scratch layer + config)
    straight through the raw ECR blob-upload API, so CreateModelPackage's image-existence
    check has a genuine image to resolve without needing docker in the sandbox."""
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w"):
        pass  # empty filesystem layer
    layer_tar = tar_buf.getvalue()
    diff_id = "sha256:" + hashlib.sha256(layer_tar).hexdigest()
    layer_gz = gzip.compress(layer_tar)
    layer_digest = _upload_blob(ecr, repo_name, layer_gz)

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
    }
    config_blob = json.dumps(config).encode("utf-8")
    config_digest = _upload_blob(ecr, repo_name, config_blob)

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_blob),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_gz),
                "digest": layer_digest,
            }
        ],
    }
    ecr.put_image(
        repositoryName=repo_name, imageManifest=json.dumps(manifest), imageTag=tag
    )


def _create_bucket(ctx, s3, suffix: str) -> str:
    bucket = ctx.unique_name(f"sim2real-sm-{suffix}-")
    # us-east-1 rejects an explicit LocationConstraint on CreateBucket; the bucket still
    # lands in ctx.region either way, so this is not a region pin.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "model-package-registry"}]},
    )
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        while True:
            contents = resp.get("Contents", [])
            if contents:
                s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in contents]},
                )
            if not resp.get("IsTruncated"):
                break
            resp = s3.list_objects_v2(
                Bucket=bucket, ContinuationToken=resp["NextContinuationToken"]
            )
    finally:
        s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
