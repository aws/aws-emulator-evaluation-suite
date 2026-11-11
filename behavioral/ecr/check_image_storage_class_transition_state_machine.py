"""image-storage-class-transition-state-machine."""
from __future__ import annotations

import gzip
import hashlib
import json
import time

from behavioral_harness import tags

CHECK = "image-storage-class-transition-state-machine"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutImage -> UpdateImageStorageClass(ARCHIVE) transitions imageStatus to ARCHIVED, and
    DescribeImageReplicationStatus still resolves the archived image by its digest."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-archive-")
    ecr.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    image_id = _push_minimal_image(ecr, repo_name, "v1")

    ecr.update_image_storage_class(
        repositoryName=repo_name, imageId=image_id, targetStorageClass="ARCHIVE"
    )

    detail = _poll_until(
        lambda: _describe_image(ecr, repo_name, image_id),
        lambda d: d is not None and d["imageStatus"] == "ARCHIVED",
        timeout_s=60.0,
    )
    assert detail["imageStatus"] == "ARCHIVED", (
        f"expected imageStatus=ARCHIVED after UpdateImageStorageClass, got {detail!r}"
    )

    repl = ecr.describe_image_replication_status(repositoryName=repo_name, imageId=image_id)
    assert repl["repositoryName"] == repo_name, (
        f"expected repositoryName={repo_name!r}, got {repl['repositoryName']!r}"
    )
    assert repl["imageId"]["imageDigest"] == image_id["imageDigest"], (
        f"expected imageDigest={image_id['imageDigest']!r} for the now-archived image, "
        f"got {repl['imageId']['imageDigest']!r}"
    )


def _push_minimal_image(ecr, repo_name: str, tag: str) -> dict:
    config_blob = b"{}"
    layer_blob = gzip.compress(b"")
    config_digest = "sha256:" + hashlib.sha256(config_blob).hexdigest()
    layer_digest = "sha256:" + hashlib.sha256(layer_blob).hexdigest()

    for blob, digest in ((config_blob, config_digest), (layer_blob, layer_digest)):
        upload = ecr.initiate_layer_upload(repositoryName=repo_name)
        ecr.upload_layer_part(
            repositoryName=repo_name,
            uploadId=upload["uploadId"],
            partFirstByte=0,
            partLastByte=len(blob) - 1,
            layerPartBlob=blob,
        )
        ecr.complete_layer_upload(
            repositoryName=repo_name, uploadId=upload["uploadId"], layerDigests=[digest]
        )

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
                "size": len(layer_blob),
                "digest": layer_digest,
            }
        ],
    }
    resp = ecr.put_image(
        repositoryName=repo_name,
        imageManifest=json.dumps(manifest),
        imageManifestMediaType="application/vnd.docker.distribution.manifest.v2+json",
        imageTag=tag,
    )
    return resp["image"]["imageId"]


def _describe_image(ecr, repo_name: str, image_id: dict):
    resp = ecr.describe_images(repositoryName=repo_name, imageIds=[image_id])
    details = resp.get("imageDetails", [])
    return details[0] if details else None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition never satisfied within {timeout_s}s (last={last!r})"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
