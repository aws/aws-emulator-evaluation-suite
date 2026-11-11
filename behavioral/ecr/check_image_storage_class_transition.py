"""image-storage-class-transition."""
from __future__ import annotations

import hashlib
import json
import os
import time

from behavioral_harness import tags

CHECK = "image-storage-class-transition"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateImageStorageClass on a real, pushed image transitions its storage class, and the
    new class is reflected in a subsequent DescribeImages call: ACTIVE -> ARCHIVED, and the
    restore call observably begins moving it back out of ARCHIVED."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-storageclass-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    image_digest = _push_minimal_image(ecr, repo_name, "v1")
    image_id = {"imageDigest": image_digest}

    detail = _describe_image(ecr, repo_name, image_id)
    assert detail["imageStatus"] == "ACTIVE", f"expected ACTIVE before any transition, got {detail['imageStatus']!r}"

    ecr.update_image_storage_class(
        repositoryName=repo_name, imageId=image_id, targetStorageClass="ARCHIVE"
    )
    archived = _poll_until(
        lambda: _describe_image(ecr, repo_name, image_id),
        lambda d: d["imageStatus"] == "ARCHIVED",
        timeout_s=60,
        interval_s=3,
    )
    assert archived["imageStatus"] == "ARCHIVED", f"expected ARCHIVED, got {archived['imageStatus']!r}"
    assert "lastArchivedAt" in archived, f"expected lastArchivedAt on an archived image, got keys {sorted(archived)}"

    ecr.update_image_storage_class(
        repositoryName=repo_name, imageId=image_id, targetStorageClass="STANDARD"
    )
    # Real AWS documents that a full restore from ECR archive can take up to 20 minutes
    # ("Restoring an image", Amazon ECR User Guide). Rather than block the suite for that
    # entire documented window, poll for the immediate, observable start of the restore
    # (status leaving ARCHIVED) which a faithful backend must reflect right away.
    restoring = _poll_until(
        lambda: _describe_image(ecr, repo_name, image_id),
        lambda d: d["imageStatus"] != "ARCHIVED",
        timeout_s=60,
        interval_s=3,
    )
    assert restoring["imageStatus"] in ("ACTIVATING", "ACTIVE"), (
        f"expected the restore to leave ARCHIVED for ACTIVATING/ACTIVE, got {restoring['imageStatus']!r}"
    )


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repo_name: str, data: bytes) -> str:
    """Uploads bytes as an ECR layer blob via the multi-step layer-upload API and returns
    its 'sha256:<hex>' digest. ECR only validates that the received bytes hash to the
    declared digest (InvalidLayerException), not that they are a valid gzip/tar."""
    digest = f"sha256:{_sha256_hex(data)}"
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest


def _push_minimal_image(ecr, repo_name: str, tag: str) -> str:
    """Pushes a minimal, valid single-layer image (config blob + one layer blob + a schema2
    manifest) through the real ECR layer-upload + PutImage flow and returns the resulting
    image digest. Each call embeds fresh random content so repeated pushes are distinct."""
    layer_bytes = b"sim2real-ecr-layer-" + os.urandom(16)
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
        "history": [{"created": "2024-01-01T00:00:00Z", "created_by": "sim2real"}],
    }
    config_bytes = json.dumps(config).encode("utf-8")
    config_digest = _upload_blob(ecr, repo_name, config_bytes)

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
    manifest_bytes = json.dumps(manifest).encode("utf-8")
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=manifest_bytes.decode("utf-8"), imageTag=tag
    )
    return resp["image"]["imageId"]["imageDigest"]


def _describe_image(ecr, repo_name: str, image_id: dict) -> dict:
    return ecr.describe_images(repositoryName=repo_name, imageIds=[image_id])["imageDetails"][0]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition never satisfied within {timeout_s}s (last={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
