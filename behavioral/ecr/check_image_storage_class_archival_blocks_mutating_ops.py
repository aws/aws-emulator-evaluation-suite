"""image-storage-class-archival-blocks-mutating-ops."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "image-storage-class-archival-blocks-mutating-ops"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartImageScan on an image moved to ARCHIVE raises ImageArchivedException while a
    never-archived sibling scans normally; a restore request moves the image out of ARCHIVED."""
    ecr = ctx.client("ecr")

    repo_name = ctx.unique_name("sim2real-ecr-archive-")
    ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _safe_delete_repository(ctx, repo_name))

    _push_minimal_image(ctx, repo_name, "v1")
    image_id = {"imageTag": "v1"}

    # Positive control: a never-archived sibling scans to a terminal status, so the rejection
    # below is attributable to archival. config_extra gives it a distinct digest; a second tag
    # on "v1" would be archived along with it.
    _push_minimal_image(ctx, repo_name, "control", config_extra={"sim2real_tag_nonce": "control"})
    control_image_id = {"imageTag": "control"}
    ecr.start_image_scan(repositoryName=repo_name, imageId=control_image_id)
    control_scan_status = _poll_until(
        lambda: ecr.describe_image_scan_findings(
            repositoryName=repo_name, imageId=control_image_id
        )["imageScanStatus"]["status"],
        lambda status: status in ("COMPLETE", "FAILED", "UNSUPPORTED_IMAGE"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert control_scan_status in ("COMPLETE", "FAILED", "UNSUPPORTED_IMAGE"), (
        f"positive control scan on non-archived image never reached a terminal "
        f"status, last={control_scan_status!r}"
    )

    archived = ecr.update_image_storage_class(
        repositoryName=repo_name, imageId=image_id, targetStorageClass="ARCHIVE"
    )
    assert archived["imageStatus"] == "ARCHIVED", (
        f"expected ARCHIVED immediately from UpdateImageStorageClass, got {archived['imageStatus']!r}"
    )
    _poll_until(
        lambda: _image_status(ecr, repo_name, "v1"),
        lambda status: status == "ARCHIVED",
        timeout_s=60.0,
        interval_s=3.0,
    )

    code, message = _error(
        lambda: ecr.start_image_scan(repositoryName=repo_name, imageId=image_id)
    )
    assert code == "ImageArchivedException", (
        f"expected StartImageScan on an ARCHIVED image to raise ImageArchivedException, got {code!r}"
    )
    assert message == (
        f"The image with imageId {{imageDigest:'null', imageTag:'v1'}} is archived within the repository with name '{repo_name}' in the registry with id '{ctx.account}'"
    ), message

    # Effect absent: no scan was actually started on the archived image.
    scan_code, scan_message = _error(
        lambda: ecr.describe_image_scan_findings(repositoryName=repo_name, imageId=image_id)
    )
    assert scan_code == "ScanNotFoundException", (
        f"expected no scan record for the archived image, got error code {scan_code!r}"
    )
    assert scan_message == (
        f"Image scan does not exist for the image with '{{imageDigest:'null', imageTag:'v1'}}' in the repository with name '{repo_name}' in the registry with id '{ctx.account}'"
    ), scan_message

    restored = ecr.update_image_storage_class(
        repositoryName=repo_name, imageId=image_id, targetStorageClass="STANDARD"
    )
    # A restore to STANDARD can take up to 20 minutes, too long to wait for, so assert the
    # immediate move out of ARCHIVED into ACTIVATING (or ACTIVE if fast).
    # https://docs.aws.amazon.com/AmazonECR/latest/userguide/archive_restore_image.html
    assert restored["imageStatus"] in ("ACTIVATING", "ACTIVE"), restored
    status_after_restore_call = _poll_until(
        lambda: _image_status(ecr, repo_name, "v1"),
        lambda status: status in ("ACTIVATING", "ACTIVE"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert status_after_restore_call in ("ACTIVATING", "ACTIVE"), status_after_restore_call
    assert status_after_restore_call != "ARCHIVED", (
        f"restore call did not move the image out of ARCHIVED, still={status_after_restore_call!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last={last}")


def _image_status(ecr, repo_name: str, tag: str) -> str:
    resp = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": tag}])
    return resp["imageDetails"][0]["imageStatus"]


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target accepting a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_repository(ctx, repo_name: str) -> None:
    ecr = ctx.client("ecr")
    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as err:
        if err.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


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
