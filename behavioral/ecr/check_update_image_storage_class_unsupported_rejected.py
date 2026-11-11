"""update-image-storage-class-unsupported-rejected."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-image-storage-class-unsupported-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateImageStorageClass from STANDARD to STANDARD on an ACTIVE image is refused
    ImageStorageClassUpdateNotSupportedException with the exact message and leaves it ACTIVE,
    while STANDARD to ARCHIVE returns ARCHIVED and DescribeImages agrees."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx, ecr)

    image = _push_minimal_image(ecr, repo, "target")
    status = _image_status(ecr, repo, image["digest"])
    assert status == "ACTIVE", f"expected ACTIVE after push, got {status!r}"

    # Unsupported: the image is already STANDARD/ACTIVE, so requesting STANDARD
    # again is not a valid transition.
    code, message = _error(
        lambda: ecr.update_image_storage_class(
            repositoryName=repo,
            imageId={"imageDigest": image["digest"]},
            targetStorageClass="STANDARD",
        )
    )
    assert code == "ImageStorageClassUpdateNotSupportedException", (
        f"expected ImageStorageClassUpdateNotSupportedException for a redundant "
        f"STANDARD request on an already-ACTIVE image, got {code!r}"
    )
    expected_message = "Image cannot be updated to STANDARD storage class when it is in ACTIVE state"
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    # Effect-absent: the image must still be ACTIVE (rejected update left no trace).
    status = _image_status(ecr, repo, image["digest"])
    assert status == "ACTIVE", f"expected ACTIVE unchanged after the rejected call, got {status!r}"

    # Positive control: the supported STANDARD -> ARCHIVE transition succeeds.
    resp = ecr.update_image_storage_class(
        repositoryName=repo,
        imageId={"imageDigest": image["digest"]},
        targetStorageClass="ARCHIVE",
    )
    assert resp["imageStatus"] == "ARCHIVED", (
        f"expected ARCHIVED in the UpdateImageStorageClass response, got {resp['imageStatus']!r}"
    )
    final_status = _poll_until(
        lambda: _image_status(ecr, repo, image["digest"]),
        lambda s: s == "ARCHIVED",
        timeout_s=60.0,
    )
    assert final_status == "ARCHIVED", (
        f"expected the independent DescribeImages read to settle on ARCHIVED, got {final_status!r}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _create_repo(ctx, ecr) -> str:
    name = ctx.unique_name("sim2real-ecr-behav-")
    ecr.create_repository(repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repo_force(ecr, name))
    return name


def _delete_repo_force(ecr, name: str) -> None:
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repo_name: str, data: bytes) -> str:
    digest = _sha256_digest(data)
    upload = ecr.initiate_layer_upload(repositoryName=repo_name)
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload["uploadId"],
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload["uploadId"], layerDigests=[digest]
    )
    return digest


def _push_minimal_image(ecr, repo_name: str, tag: str) -> dict:
    config_bytes = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": []},
            "sim2real_tag_nonce": tag,
        }
    ).encode()
    layer_bytes = f"sim2real-ecr-behavioral-layer-blob-{tag}".encode()
    config_digest = _upload_blob(ecr, repo_name, config_bytes)
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)
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
    manifest_bytes = json.dumps(manifest).encode()
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=manifest_bytes.decode(), imageTag=tag
    )
    image = resp["image"]
    return {
        "digest": image["imageId"]["imageDigest"],
        "tag": tag,
        "manifest_bytes": manifest_bytes,
    }


def _image_status(ecr, repo_name: str, digest: str) -> str:
    resp = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageDigest": digest}])
    return resp["imageDetails"][0]["imageStatus"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

