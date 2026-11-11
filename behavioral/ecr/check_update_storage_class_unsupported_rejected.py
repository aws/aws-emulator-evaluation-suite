"""update-storage-class-unsupported-rejected."""
from __future__ import annotations

import hashlib
import json
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-storage-class-unsupported-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateImageStorageClass to ARCHIVE on an ARCHIVED image is refused
    ImageStorageClassUpdateNotSupportedException with the exact message and the image stays
    ARCHIVED, while a transition to STANDARD is accepted and moves it to ACTIVATING or ACTIVE."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-storageclassneg-")
    ecr.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    image = _push_minimal_image(ecr, repo_name, "already-archived")
    digest = image["imageId"]["imageDigest"]

    # positive control: a genuine ACTIVE -> ARCHIVE transition succeeds
    ecr.update_image_storage_class(
        repositoryName=repo_name,
        imageId={"imageDigest": digest},
        targetStorageClass="ARCHIVE",
    )
    archived_status = _poll_until(
        lambda: _status(ecr, repo_name, digest),
        lambda status: status == "ARCHIVED",
        timeout_s=30.0,
    )
    assert archived_status == "ARCHIVED", (
        f"expected ARCHIVED after the initial ACTIVE->ARCHIVE transition, saw {archived_status!r}"
    )

    # break: request ARCHIVE again on an image already in ARCHIVE
    code, message = _error(
        lambda: ecr.update_image_storage_class(
            repositoryName=repo_name,
            imageId={"imageDigest": digest},
            targetStorageClass="ARCHIVE",
        )
    )
    assert code == "ImageStorageClassUpdateNotSupportedException", (
        f"expected ImageStorageClassUpdateNotSupportedException for a redundant ARCHIVE "
        f"request on an already-ARCHIVED image, got {code!r}"
    )
    expected_message = "Image cannot be updated to ARCHIVE storage class when it is in ARCHIVED state"
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    # effect absent: independent read, not the mutating call's own response
    unperturbed_status = _status(ecr, repo_name, digest)
    assert unperturbed_status == "ARCHIVED", (
        f"expected the image to remain ARCHIVED after the rejected call, saw {unperturbed_status!r}"
    )

    # restore: the same image accepts a transition away from ARCHIVE. Full settlement
    # to ACTIVE can take AWS up to ~20 minutes per the docs, well past this check's
    # budget, so this asserts the transition is accepted and under way, not settled.
    restore = ecr.update_image_storage_class(
        repositoryName=repo_name,
        imageId={"imageDigest": digest},
        targetStorageClass="STANDARD",
    )
    assert restore["imageId"]["imageDigest"] == digest, (
        f"expected the accepted restore to name digest {digest!r}, got {restore.get('imageId')!r}"
    )
    # independent read, not the mutating call's own response
    restored_status = _poll_until(
        lambda: _status(ecr, repo_name, digest),
        lambda status: status in ("ACTIVATING", "ACTIVE"),
        timeout_s=30.0,
    )
    assert restored_status in ("ACTIVATING", "ACTIVE"), (
        f"expected the restore to leave the image ACTIVATING or ACTIVE, saw {restored_status!r}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _status(ecr, repo_name: str, digest: str) -> str:
    return ecr.describe_images(
        repositoryName=repo_name, imageIds=[{"imageDigest": digest}]
    )["imageDetails"][0]["imageStatus"]


def _upload_blob(ecr, repo_name: str, data: bytes) -> tuple[str, int]:
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest, len(data)


def _push_minimal_image(ecr, repo_name: str, tag: str) -> dict:
    config_digest, config_size = _upload_blob(ecr, repo_name, json.dumps({"sim2real": tag}).encode())
    layer_digest, layer_size = _upload_blob(ecr, repo_name, os.urandom(128))
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


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
