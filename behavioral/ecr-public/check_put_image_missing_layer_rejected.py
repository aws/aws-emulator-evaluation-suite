"""put-image-missing-layer-rejected."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from behavioral_harness import tags

CHECK = "put-image-missing-layer-rejected"
GROUP = "e2e"
SERVICES = ["ecr-public"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutImage with a manifest referencing a never-uploaded layer fails with LayersNotFoundException
    and creates no image or tag; the same manifest succeeds once the layer is uploaded."""
    ecrpublic = _ecrpublic(ctx)
    repo_name = ctx.unique_name("sim2real-ecrpub-missinglayer-")

    ecrpublic.create_repository(
        repositoryName=repo_name,
        tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecrpublic.delete_repository(repositoryName=repo_name, force=True))

    # A layer digest that was never uploaded to this repository at all.
    phantom_bytes = b"never-uploaded-" + os.urandom(64)
    phantom_digest = "sha256:" + hashlib.sha256(phantom_bytes).hexdigest()
    config_bytes = json.dumps(
        {"architecture": "amd64", "os": "linux", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}}
    ).encode()
    config_digest = _upload_single_part_layer(ctx, repo_name, config_bytes)

    # Precondition: the phantom layer really is unknown to the registry before PutImage
    # is attempted, so the rejection below can only be about the missing layer.
    availability = ecrpublic.batch_check_layer_availability(
        repositoryName=repo_name, layerDigests=[phantom_digest]
    )
    reported = {
        item["layerDigest"]: item["layerAvailability"] for item in availability.get("layers", [])
    }
    assert reported.get(phantom_digest) != "AVAILABLE", (
        f"precondition: the phantom layer must not already be available; got {availability}"
    )

    manifest_str = _build_manifest(config_digest, len(config_bytes), phantom_digest, len(phantom_bytes))

    code, code_msg = _error_code(
        lambda: ecrpublic.put_image(
            repositoryName=repo_name,
            imageManifest=manifest_str,
            imageManifestMediaType="application/vnd.docker.distribution.manifest.v2+json",
            imageTag="missing-layer",
        )
    )
    assert code == "LayersNotFoundException", f"expected LayersNotFoundException, got {code!r}"
    expected_code_msg = f"Layers with digests '[{phantom_digest}]' required for pushing image into repository with name '{repo_name}' in the registry with id '{ctx.account}' do not exist"
    assert code_msg == expected_code_msg, f"expected message {expected_code_msg!r}, got {code_msg!r}"

    # Effect absent: no image and no tag was created by the rejected push.
    images_resp = ecrpublic.describe_images(repositoryName=repo_name)
    assert images_resp["imageDetails"] == [], (
        f"a rejected PutImage must not create an image: {images_resp['imageDetails']}"
    )
    tags_resp = ecrpublic.describe_image_tags(repositoryName=repo_name)
    tags = {t["imageTag"] for t in tags_resp["imageTagDetails"]}
    assert "missing-layer" not in tags, "a rejected PutImage must not create the tag"

    # Positive control: really upload the layer, then the identical manifest succeeds.
    real_digest = _upload_single_part_layer(ctx, repo_name, phantom_bytes)
    assert real_digest == phantom_digest, "sanity: uploaded bytes must hash to the digest we referenced"

    put_ok = ecrpublic.put_image(
        repositoryName=repo_name,
        imageManifest=manifest_str,
        imageManifestMediaType="application/vnd.docker.distribution.manifest.v2+json",
        imageTag="missing-layer",
    )
    assert put_ok["image"]["imageId"]["imageDigest"], (
        f"the identical manifest must succeed once its layer is uploaded: {put_ok}"
    )

    tags_resp2 = ecrpublic.describe_image_tags(repositoryName=repo_name)
    tags2 = {t["imageTag"] for t in tags_resp2["imageTagDetails"]}
    assert "missing-layer" in tags2, "the same manifest must succeed once its layer is actually uploaded"


def _ecrpublic(ctx: Any):
    """A ctx client for ecr-public pinned to us-east-1, the only region that serves it;
    ctx.client keeps the target's endpoint, so one code path serves AWS and an emulator."""
    return ctx.client("ecr-public", region="us-east-1")


def _upload_single_part_layer(ctx: Any, repo_name: str, data: bytes) -> str:
    ecrpublic = _ecrpublic(ctx)
    init = ecrpublic.initiate_layer_upload(repositoryName=repo_name)
    upload_id = init["uploadId"]
    ecrpublic.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    ecrpublic.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest


def _build_manifest(config_digest: str, config_size: int, layer_digest: str, layer_size: int) -> str:
    return json.dumps(
        {
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
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
