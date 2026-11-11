"""update-image-storage-class-double-archive-rejected."""
from __future__ import annotations

import gzip
import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-image-storage-class-double-archive-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Archiving an already-ARCHIVED image raises ImageStorageClassUpdateNotSupportedException;
    the image stays ARCHIVED, and restoring it to STANDARD is still accepted."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-storageclass-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    digest, _ = _push_test_image(ecr, repo_name, "v1", seed=b"storage-class-payload")
    image_id = {"imageDigest": digest}

    archive_resp = ecr.update_image_storage_class(
        repositoryName=repo_name, imageId=image_id, targetStorageClass="ARCHIVE"
    )
    assert archive_resp["imageStatus"] == "ARCHIVED", (
        f"expected ARCHIVED from the accepted transition, got {archive_resp['imageStatus']!r}"
    )
    status = _poll_until(
        lambda: _current_status(ecr, repo_name, digest),
        lambda s: s == "ARCHIVED",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert status == "ARCHIVED", f"expected the image to settle at ARCHIVED, saw {status!r}"

    code, message = _client_error(lambda: ecr.update_image_storage_class(
        repositoryName=repo_name, imageId=image_id, targetStorageClass="ARCHIVE"
    ))
    assert code == "ImageStorageClassUpdateNotSupportedException", (
        f"expected ImageStorageClassUpdateNotSupportedException for archiving an "
        f"already-ARCHIVED image, got {code!r}"
    )
    assert message == (
        "Image cannot be updated to ARCHIVE storage class when it is in ARCHIVED state"
    ), message

    recheck_status = _current_status(ecr, repo_name, digest)
    assert recheck_status == "ARCHIVED", (
        f"the rejected double-archive must leave the image ARCHIVED, saw {recheck_status!r}"
    )

    # A full restore can take ~20 minutes, so only the accepted transition is asserted.
    restore_resp = ecr.update_image_storage_class(
        repositoryName=repo_name, imageId=image_id, targetStorageClass="STANDARD"
    )
    assert restore_resp["imageStatus"] in ("ACTIVATING", "ACTIVE"), (
        f"expected the restore to STANDARD to be accepted into ACTIVATING/ACTIVE, "
        f"got {restore_resp['imageStatus']!r}"
    )
    settled_status = _poll_until(
        lambda: _current_status(ecr, repo_name, digest),
        lambda s: s in ("ACTIVATING", "ACTIVE"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert settled_status in ("ACTIVATING", "ACTIVE"), (
        f"restore did not leave the image in a restoring/active state, saw {settled_status!r}"
    )



def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


def _current_status(ecr, repo_name: str, digest: str) -> str:
    details = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageDigest": digest}])["imageDetails"]
    assert len(details) == 1, f"expected exactly one image detail, got {len(details)}"
    return details[0]["imageStatus"]


def _upload_blob(ecr, repo_name: str, data: bytes) -> str:
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    upload = ecr.initiate_layer_upload(repositoryName=repo_name)
    upload_id = upload["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest


def _push_test_image(ecr, repo_name: str, tag: str, *, seed: bytes):
    layer_bytes = gzip.compress(b"sim2real-ecr-behavioral-layer:" + seed)
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)
    config_bytes = json.dumps({
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
    }).encode("utf-8")
    config_digest = _upload_blob(ecr, repo_name, config_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [{
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "size": len(layer_bytes),
            "digest": layer_digest,
        }],
    }
    manifest_text = json.dumps(manifest)
    resp = ecr.put_image(repositoryName=repo_name, imageManifest=manifest_text, imageTag=tag)
    return resp["image"]["imageId"]["imageDigest"], manifest_text


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
