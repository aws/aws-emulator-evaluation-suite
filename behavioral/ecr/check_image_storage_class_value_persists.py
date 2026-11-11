"""image-storage-class-value-persists."""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
import time
import uuid

from behavioral_harness import tags

CHECK = "image-storage-class-value-persists"
GROUP = "representation"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After UpdateImageStorageClass transitions an image to ARCHIVE, DescribeImages reports
    the same imageStatus that the mutating call itself returned -- not merely the API
    response of the mutation."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-storclass-").lower()
    ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _delete_repository_ignore_missing(ecr, repo_name))

    digest = _push_minimal_image(ecr, repo_name, "v1")

    response = ecr.update_image_storage_class(
        repositoryName=repo_name,
        imageId={"imageDigest": digest},
        targetStorageClass="ARCHIVE",
    )
    assert response["imageStatus"] == "ARCHIVED", (
        f"expected UpdateImageStorageClass to report ARCHIVED, got {response['imageStatus']!r}"
    )

    detail = _poll_until(
        lambda: ecr.describe_images(
            repositoryName=repo_name, imageIds=[{"imageDigest": digest}]
        )["imageDetails"][0],
        lambda detail: detail["imageStatus"] == "ARCHIVED",
        timeout_s=60.0,
    )
    assert detail["imageStatus"] == "ARCHIVED", (
        f"expected an independent DescribeImages to agree with the mutating "
        f"call's own ARCHIVED response, got {detail['imageStatus']!r}"
    )
    assert "lastArchivedAt" in detail, (
        "DescribeImages must carry lastArchivedAt once archived -- state that "
        "UpdateImageStorageClass's own response never reports"
    )


def _delete_repository_ignore_missing(ecr, repo_name) -> None:
    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ecr.exceptions.RepositoryNotFoundException:
        pass


def _empty_gzip_tar_blob() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz"):
        pass
    return buf.getvalue()


def _push_minimal_image(ecr, repo_name: str, tag: str) -> str:
    layer_bytes = _empty_gzip_tar_blob()
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    config_obj = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Labels": {"sim2real-nonce": str(uuid.uuid4())}},
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
    }
    config_bytes = json.dumps(config_obj).encode("utf-8")
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()

    for blob, digest in ((config_bytes, config_digest), (layer_bytes, layer_digest)):
        upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
        ecr.upload_layer_part(
            repositoryName=repo_name,
            uploadId=upload_id,
            partFirstByte=0,
            partLastByte=len(blob) - 1,
            layerPartBlob=blob,
        )
        try:
            ecr.complete_layer_upload(
                repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
            )
        except ecr.exceptions.LayerAlreadyExistsException:
            pass  # layer content already stored in this repository; benign reuse

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_bytes),
                "digest": layer_digest,
            }
        ],
    }
    put_response = ecr.put_image(
        repositoryName=repo_name,
        imageManifest=json.dumps(manifest),
        imageTag=tag,
    )
    return put_response["image"]["imageId"]["imageDigest"]


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition never satisfied within {timeout_s}s, last value={value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
