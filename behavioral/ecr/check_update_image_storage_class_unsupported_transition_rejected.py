"""update-image-storage-class-unsupported-transition-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-image-storage-class-unsupported-transition-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Re-archiving an already ARCHIVED image is rejected with
    ImageStorageClassUpdateNotSupportedException and leaves its status unchanged, while
    archiving a still-ACTIVE image in the same repository succeeds."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx)

    image = _push_image(ctx, repo["repositoryName"], tag="already-archived")
    first = ecr.update_image_storage_class(
        repositoryName=repo["repositoryName"],
        imageId={"imageDigest": image["imageId"]["imageDigest"]},
        targetStorageClass="ARCHIVE",
    )
    assert first["imageStatus"] == "ARCHIVED", (
        f"expected the initial ACTIVE->ARCHIVE transition to report ARCHIVED, got {first['imageStatus']!r}"
    )

    code, message = _error(
        lambda: ecr.update_image_storage_class(
            repositoryName=repo["repositoryName"],
            imageId={"imageDigest": image["imageId"]["imageDigest"]},
            targetStorageClass="ARCHIVE",
        )
    )
    assert code == "ImageStorageClassUpdateNotSupportedException", (
        f"expected re-archiving an already-ARCHIVED image to be rejected with "
        f"ImageStorageClassUpdateNotSupportedException, got {code!r}"
    )
    expected_message = "Image cannot be updated to ARCHIVE storage class when it is in ARCHIVED state"
    assert message == expected_message, (
        f"expected the exact refusal message {expected_message!r}, got {message!r}"
    )

    detail = ecr.describe_images(
        repositoryName=repo["repositoryName"], imageIds=[{"imageDigest": image["imageId"]["imageDigest"]}]
    )["imageDetails"][0]
    assert detail["imageStatus"] == "ARCHIVED", (
        f"expected the rejected re-archive to leave the image ARCHIVED, an independent "
        f"describe_images read saw {detail['imageStatus']!r}"
    )

    other = _push_image(ctx, repo["repositoryName"], tag="still-active")
    second = ecr.update_image_storage_class(
        repositoryName=repo["repositoryName"],
        imageId={"imageDigest": other["imageId"]["imageDigest"]},
        targetStorageClass="ARCHIVE",
    )
    assert second["imageStatus"] == "ARCHIVED", (
        f"expected the fresh ACTIVE->ARCHIVE transition on a sibling image to succeed, "
        f"got {second['imageStatus']!r}"
    )

    other_detail = ecr.describe_images(
        repositoryName=repo["repositoryName"], imageIds=[{"imageDigest": other["imageId"]["imageDigest"]}]
    )["imageDetails"][0]
    assert other_detail["imageStatus"] == "ARCHIVED", (
        f"expected an independent describe_images read to confirm the sibling image is "
        f"ARCHIVED, saw {other_detail['imageStatus']!r}"
    )


import hashlib
import json
import time

_MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
_CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
_LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_repo(ctx, **kwargs):
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


def _upload_blob(ecr, repo_name, data):
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
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


def _push_image(ctx, repo_name, tag=None):
    ecr = ctx.client("ecr")
    unique = f"{repo_name}-{time.time_ns()}"
    config_bytes = json.dumps(
        {"architecture": "amd64", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}, "unique": unique}
    ).encode()
    layer_bytes = f"sim2real-ecr-layer-{unique}".encode()
    config_digest = _upload_blob(ecr, repo_name, config_bytes)
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": _MANIFEST_MEDIA_TYPE,
        "config": {"mediaType": _CONFIG_MEDIA_TYPE, "size": len(config_bytes), "digest": config_digest},
        "layers": [{"mediaType": _LAYER_MEDIA_TYPE, "size": len(layer_bytes), "digest": layer_digest}],
    }
    kwargs = {"repositoryName": repo_name, "imageManifest": json.dumps(manifest)}
    if tag:
        kwargs["imageTag"] = tag
    return ecr.put_image(**kwargs)["image"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
