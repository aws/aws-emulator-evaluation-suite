"""start-image-scan-archived-image-blocked."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-image-scan-archived-image-blocked"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartImageScan on an image whose storage class has been moved to ARCHIVE is rejected
    with ImageArchivedException and never starts a scan, while the same call against a
    still-active image in the same repository succeeds (positive control)."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-repo-")
    ecr.create_repository(
        repositoryName=repo_name,
        imageScanningConfiguration={"scanOnPush": False},
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    active_image = _push_minimal_image(ecr, repo_name, "active")
    archived_image = _push_minimal_image(ecr, repo_name, "archived")

    resp = ecr.update_image_storage_class(
        repositoryName=repo_name, imageId=archived_image, targetStorageClass="ARCHIVE"
    )
    assert resp["imageStatus"] == "ARCHIVED"
    _poll_until_status(ecr, repo_name, archived_image, "ARCHIVED")

    code, message = _client_error(
        lambda: ecr.start_image_scan(repositoryName=repo_name, imageId=archived_image)
    )
    assert code == "ImageArchivedException", code
    assert message == (
        f"The image with imageId {{imageDigest:'{archived_image['imageDigest']}', "
        f"imageTag:'{archived_image['imageTag']}'}} is archived within the repository with name "
        f"'{repo_name}' in the registry with id '{ctx.account}'"
    ), message

    # Effect absent: no scan was ever started for the archived image.
    findings_code, findings_message = _client_error(
        lambda: ecr.describe_image_scan_findings(repositoryName=repo_name, imageId=archived_image)
    )
    assert findings_code == "ScanNotFoundException", findings_code
    assert findings_message == (
        f"Image scan does not exist for the image with '{{imageDigest:'{archived_image['imageDigest']}', "
        f"imageTag:'{archived_image['imageTag']}'}}' in the repository with name '{repo_name}' "
        f"in the registry with id '{ctx.account}'"
    ), findings_message

    # Positive control: the still-active image in the same repository can be scanned,
    # and the scan is independently observable at the destination (describe_image_scan_findings)
    # rather than trusting start_image_scan's own response, all the way to a terminal status.
    scan_resp = ecr.start_image_scan(repositoryName=repo_name, imageId=active_image)
    assert scan_resp["imageScanStatus"]["status"] in ("IN_PROGRESS", "PENDING", "COMPLETE")

    terminal_status = _poll_until_scan_terminal(ecr, repo_name, active_image)
    assert terminal_status in ("COMPLETE", "FAILED", "UNSUPPORTED_IMAGE"), terminal_status


def _client_error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until_status(ecr, repo_name, image_id, expected_status, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = ecr.describe_images(repositoryName=repo_name, imageIds=[image_id])
        details = resp["imageDetails"]
        if details:
            last = details[0].get("imageStatus")
            if last == expected_status:
                return
        time.sleep(interval_s)
    raise AssertionError(f"image never reached status {expected_status!r} (last={last!r})")


def _poll_until_scan_terminal(ecr, repo_name, image_id, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = ecr.describe_image_scan_findings(repositoryName=repo_name, imageId=image_id)
        last = resp["imageScanStatus"]["status"]
        if last in ("COMPLETE", "FAILED", "UNSUPPORTED_IMAGE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"scan never reached a terminal status (last={last!r})")


def _push_minimal_image(ecr, repo_name, tag):
    """Push a minimal, synthetic Docker v2 schema-2 image directly through the ECR blob-upload
    and PutImage APIs (no docker daemon needed) and return its ImageIdentifier."""
    config_bytes = (
        b'{"architecture":"amd64","os":"linux","config":{},'
        b'"rootfs":{"type":"layers","diff_ids":[]},"variant":"'
        + tag.encode() + b'-' + repo_name.encode() + b'"}'
    )
    layer_bytes = b"sim2real-ecr-behavioral-fidelity-layer-" + repo_name.encode() + tag.encode()

    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()

    for blob, digest in ((config_bytes, config_digest), (layer_bytes, layer_digest)):
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
    result = ecr.put_image(
        repositoryName=repo_name, imageManifest=json.dumps(manifest), imageTag=tag
    )
    return result["image"]["imageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
