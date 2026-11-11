"""deploy-ecr-repository-cfn-then-push-image-succeeds."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile

from behavioral_harness import tags

CHECK = "deploy-ecr-repository-cfn-then-push-image-succeeds"
GROUP = "deploy"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A repository deployed via CloudFormation actually accepts a real image
    push (layer upload + PutImage) and the pushed layer/manifest can be fetched
    back afterward -- not merely CREATE_COMPLETE on the stack."""
    ecr = ctx.client("ecr")
    cfn = ctx.client("cloudformation")

    repo_name = ctx.unique_name("sim2real-ecr-cfn-")
    stack_name = ctx.unique_name("sim2real-ecr-cfn-stack-")
    template = json.dumps(
        {
            "Resources": {
                "Repo": {
                    "Type": "AWS::ECR::Repository",
                    "Properties": {
                        "RepositoryName": repo_name,
                        "EmptyOnDelete": True,
                    },
                }
            }
        }
    )

    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    # Reaching CREATE_COMPLETE is not the interesting part: prove the repo
    # actually accepts the real ECR data-plane push flow afterward.
    image = _push_minimal_image(ctx, repo_name, "v1")
    pushed_digest = image["imageId"]["imageDigest"]

    fetched = ecr.batch_get_image(
        repositoryName=repo_name, imageIds=[{"imageTag": "v1"}]
    )
    assert not fetched["failures"], f"unexpected failures: {fetched['failures']}"
    assert len(fetched["images"]) == 1, (
        f"expected exactly 1 image for tag 'v1', got {len(fetched['images'])}"
    )
    fetched_image = fetched["images"][0]
    assert fetched_image["imageId"]["imageDigest"] == pushed_digest, (
        f"expected fetched digest {pushed_digest!r}, "
        f"got {fetched_image['imageId']['imageDigest']!r}"
    )
    fetched_schema_version = json.loads(fetched_image["imageManifest"])["schemaVersion"]
    assert fetched_schema_version == 2, (
        f"expected manifest schemaVersion 2, got {fetched_schema_version!r}"
    )

    layer_digest = json.loads(fetched_image["imageManifest"])["layers"][0]["digest"]
    avail = ecr.batch_check_layer_availability(
        repositoryName=repo_name, layerDigests=[layer_digest]
    )
    layer_availability = avail["layers"][0]["layerAvailability"]
    assert layer_availability == "AVAILABLE", (
        f"expected layer {layer_digest!r} to be AVAILABLE, got {layer_availability!r}"
    )


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _upload_blob(ecr, repo_name: str, blob_bytes: bytes) -> tuple[str, int]:
    digest = "sha256:" + hashlib.sha256(blob_bytes).hexdigest()
    avail = ecr.batch_check_layer_availability(
        repositoryName=repo_name, layerDigests=[digest]
    )
    if avail["layers"] and avail["layers"][0]["layerAvailability"] == "AVAILABLE":
        return digest, avail["layers"][0]["layerSize"]
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob_bytes) - 1,
        layerPartBlob=blob_bytes,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest, len(blob_bytes)


def _push_minimal_image(ctx, repo_name: str, tag: str, config_extra: dict | None = None):
    """Pushes a minimal (scratch) OCI-ish image via the raw ECR layer-upload
    API, without needing docker: build an empty gzipped tar layer + a minimal
    JSON image config, upload both as blobs, then PutImage a v2 manifest."""
    ecr = ctx.client("ecr")

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w"):
        pass
    tar_bytes = tar_buf.getvalue()
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    gz_bytes = gz_buf.getvalue()

    layer_digest, layer_size = _upload_blob(ecr, repo_name, gz_bytes)
    diff_id = "sha256:" + hashlib.sha256(tar_bytes).hexdigest()

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "history": [{"created": "2024-01-01T00:00:00Z"}],
    }
    if config_extra:
        config.update(config_extra)
    config_bytes = json.dumps(config).encode("utf-8")
    config_digest, config_size = _upload_blob(ecr, repo_name, config_bytes)

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": config_size,
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": layer_size,
                "digest": layer_digest,
            }
        ],
    }
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=json.dumps(manifest), imageTag=tag
    )
    return resp["image"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
