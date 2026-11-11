"""image-scan-on-archived-image-rejected."""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
import time
import uuid

from behavioral_harness import tags

CHECK = "image-scan-on-archived-image-rejected"
GROUP = "representation"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """StartImageScan on an ARCHIVE-class image raises ImageArchivedException and records no scan,
    while an ACTIVE sibling scans to a terminal status; the restore request leaves ARCHIVED."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-scanarch-").lower()
    ecr.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: _delete_repository_ignore_missing(ecr, repo_name))
    _ensure_basic_scanning_enabled(ctx, ecr)

    # Positive control up front: scanning succeeds while nothing is archived yet, so a
    # later rejection cannot be confused with "this account/repo can never scan".
    control_digest = _push_minimal_image(ecr, repo_name, "control")
    ecr.start_image_scan(repositoryName=repo_name, imageId={"imageDigest": control_digest})
    control_result = _poll_scan_to_terminal(ecr, repo_name, control_digest)
    # The synthetic OS-less image reaches the terminal status basic scanning gives it.
    assert control_result == {
        "status": "FAILED",
        "description": "UnsupportedImageError: The operating system and/or package manager are not supported.",
    }, control_result

    archived_digest = _push_minimal_image(ecr, repo_name, "to-archive")
    ecr.update_image_storage_class(
        repositoryName=repo_name,
        imageId={"imageDigest": archived_digest},
        targetStorageClass="ARCHIVE",
    )
    _poll_until(
        lambda: _image_status(ecr, repo_name, archived_digest),
        lambda status: status == "ARCHIVED",
        timeout_s=60.0,
    )

    error = _client_error(
        lambda: ecr.start_image_scan(
            repositoryName=repo_name, imageId={"imageDigest": archived_digest}
        )
    )
    image_ref = f"{{imageDigest:'{archived_digest}', imageTag:'null'}}"
    assert error == {
        "Code": "ImageArchivedException",
        "Message": (
            f"The image with imageId {image_ref} is archived within the repository with name "
            f"'{repo_name}' in the registry with id '{ctx.account}'"
        ),
    }, error

    # Effect absent: no scan was ever recorded for the archived image.
    scan_error = _client_error(
        lambda: ecr.describe_image_scan_findings(
            repositoryName=repo_name, imageId={"imageDigest": archived_digest}
        )
    )
    assert scan_error == {
        "Code": "ScanNotFoundException",
        "Message": (
            f"Image scan does not exist for the image with '{image_ref}' in the repository "
            f"with name '{repo_name}' in the registry with id '{ctx.account}'"
        ),
    }, scan_error

    # Restore is accepted and leaves the terminal ARCHIVED state, so the block is tied to the
    # reversible storage class. Full reactivation takes too long to wait for in a bounded check.
    restore_resp = ecr.update_image_storage_class(
        repositoryName=repo_name,
        imageId={"imageDigest": archived_digest},
        targetStorageClass="STANDARD",
    )
    assert restore_resp["imageStatus"] in ("ACTIVATING", "ACTIVE"), restore_resp
    status_after_restore_request = _image_status(ecr, repo_name, archived_digest)
    assert status_after_restore_request != "ARCHIVED", status_after_restore_request


def _image_status(ecr, repo_name: str, digest: str) -> str:
    return ecr.describe_images(
        repositoryName=repo_name, imageIds=[{"imageDigest": digest}]
    )["imageDetails"][0]["imageStatus"]


def _poll_scan_to_terminal(ecr, repo_name: str, digest: str) -> dict:
    return _poll_until(
        lambda: ecr.describe_image_scan_findings(
            repositoryName=repo_name, imageId={"imageDigest": digest}
        )["imageScanStatus"],
        lambda st: st["status"] in ("COMPLETE", "FAILED", "UNSUPPORTED_IMAGE"),
        timeout_s=120.0,
        interval_s=5.0,
    )


def _ensure_basic_scanning_enabled(ctx, ecr) -> None:
    """StartImageScan raises ValidationException ("This feature is disabled") if the
    registry's scanning configuration doesn't have basic scanning enabled. This is an
    account/region-global singleton, so save and restore whatever was there before."""
    original = ecr.get_registry_scanning_configuration()["scanningConfiguration"]

    def _restore():
        ecr.put_registry_scanning_configuration(
            scanType=original.get("scanType", "BASIC"),
            rules=original.get("rules", []),
        )

    ctx.on_cleanup(_restore)
    # Empty rules => BASIC scanning capability is enabled registry-wide but no repository
    # auto-scans on push, so our explicit StartImageScan calls are the only scans triggered.
    ecr.put_registry_scanning_configuration(scanType="BASIC", rules=[])


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
            pass

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


def _client_error(fn) -> dict:
    """The {Code, Message} of the ClientError fn raises; fails loudly if fn succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return {"Code": err.response["Error"]["Code"], "Message": err.response["Error"]["Message"]}
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
