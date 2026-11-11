"""update-image-storage-class-transition."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time

from behavioral_harness import tags

CHECK = "update-image-storage-class-transition"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateImageStorageClass transitions an image STANDARD -> ARCHIVE -> STANDARD and
    DescribeImages reflects each new imageStatus."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-storageclass-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    digest = _push_minimal_image(ecr, repo_name, "v1", ctx.unique_name("m"))
    image_id = {"imageDigest": digest}

    initial = ecr.describe_images(repositoryName=repo_name, imageIds=[image_id])["imageDetails"]
    assert len(initial) == 1
    assert initial[0]["imageStatus"] == "ACTIVE"

    archive_resp = ecr.update_image_storage_class(
        repositoryName=repo_name, imageId=image_id, targetStorageClass="ARCHIVE"
    )
    assert archive_resp["imageStatus"] == "ARCHIVED"

    # The mutating call's own response is not proof the target's read side agrees, so poll
    # the independent DescribeImages read to its terminal ARCHIVED state (bounded retry:
    # archival is not guaranteed instantaneous on the read path).
    archived = _poll_until(
        lambda: _describe_images(ecr, repo_name, image_id),
        lambda ds: len(ds) == 1 and ds[0]["imageStatus"] == "ARCHIVED",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert len(archived) == 1
    assert archived[0]["imageStatus"] == "ARCHIVED"

    restore_resp = ecr.update_image_storage_class(
        repositoryName=repo_name, imageId=image_id, targetStorageClass="STANDARD"
    )
    assert restore_resp["imageStatus"] == "ACTIVATING", restore_resp

    # A restore from archive is documented to take up to about 20 minutes; poll the read side
    # until the image is back to its terminal ACTIVE status.
    restored = _poll_until(
        lambda: _describe_images(ecr, repo_name, image_id),
        lambda ds: len(ds) == 1 and ds[0]["imageStatus"] == "ACTIVE",
        timeout_s=1500.0,
        interval_s=15.0,
    )
    assert len(restored) == 1
    assert restored[0]["imageStatus"] == "ACTIVE"


def _describe_images(ecr, repo_name: str, image_id: dict) -> list:
    return ecr.describe_images(repositoryName=repo_name, imageIds=[image_id])["imageDetails"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition never satisfied within {timeout_s}s (last={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _build_layer_and_config(marker: str):
    payload = f"sim2real-behav-{marker}".encode("utf-8")
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        info = tarfile.TarInfo(name="marker.txt")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    tar_bytes = tar_buf.getvalue()
    gz_bytes = gzip.compress(tar_bytes, compresslevel=6)
    diff_id = "sha256:" + hashlib.sha256(tar_bytes).hexdigest()
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "comment": f"sim2real-behav-{marker}",
    }
    config_bytes = json.dumps(config).encode("utf-8")
    return gz_bytes, config_bytes


def _upload_blob(ecr, repo_name: str, data: bytes) -> tuple[str, int]:
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    init = ecr.initiate_layer_upload(repositoryName=repo_name)
    upload_id = init["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest, len(data)


def _push_minimal_image(ecr, repo_name: str, tag: str, marker: str) -> str:
    gz_bytes, config_bytes = _build_layer_and_config(marker)
    config_digest, config_size = _upload_blob(ecr, repo_name, config_bytes)
    layer_digest, layer_size = _upload_blob(ecr, repo_name, gz_bytes)
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
    manifest_str = json.dumps(manifest)
    resp = ecr.put_image(repositoryName=repo_name, imageManifest=manifest_str, imageTag=tag)
    return resp["image"]["imageId"]["imageDigest"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
