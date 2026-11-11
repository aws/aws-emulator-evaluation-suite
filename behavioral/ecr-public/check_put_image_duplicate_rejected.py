"""put-image-duplicate-rejected."""
from __future__ import annotations

import hashlib
import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-image-duplicate-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr-public"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Re-pushing the byte-identical manifest under the same tag must be rejected with
    ImageAlreadyExistsException, not silently accepted as a no-op success."""
    ecr = ctx.client("ecr-public")
    name = ctx.unique_name("sim2real-behav-ecrp-dupimage-")
    ecr.create_repository(repositoryName=name)
    ctx.on_cleanup(lambda: _force_delete_repository(ecr, name))

    image_digest, manifest_str, _cfg, _layer = _push_image(ecr, name, "stable")

    code, code_msg = _error_code(
        lambda: ecr.put_image(
            repositoryName=name,
            imageManifest=manifest_str,
            imageManifestMediaType="application/vnd.docker.distribution.manifest.v2+json",
            imageTag="stable",
            imageDigest=image_digest,
        )
    )
    assert code == "ImageAlreadyExistsException", code
    expected_code_msg = f"Image with digest '{image_digest}' and tag 'stable' already exists in the repository with name '{name}' in registry with id '{ctx.account}'"
    assert code_msg == expected_code_msg, f"expected message {expected_code_msg!r}, got {code_msg!r}"

    # the repository must still hold exactly one image for that tag
    images = ecr.describe_images(repositoryName=name, imageIds=[{"imageTag": "stable"}])
    assert len(images["imageDetails"]) == 1, images
    assert images["imageDetails"][0]["imageDigest"] == image_digest, images


def _error_code(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this duplicate push, but it SUCCEEDED and returned {result!r}")


def _force_delete_repository(ecr, name: str) -> None:
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repository_name: str, blob: bytes) -> str:
    """Full initiate -> upload-part -> complete layer-upload cycle for one blob."""
    digest = _sha256_digest(blob)
    upload_id = ecr.initiate_layer_upload(repositoryName=repository_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repository_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    ecr.complete_layer_upload(
        repositoryName=repository_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


def _build_manifest(ecr, repository_name: str, salt: str | None = None):
    """Upload a config blob + a layer blob; return (manifest_bytes, config_digest, layer_digest)."""
    salt = salt or uuid.uuid4().hex
    config_bytes = json.dumps(
        {"architecture": "amd64", "os": "linux", "config": {}, "salt": salt}
    ).encode()
    layer_bytes = (b"layer-blob-" + salt.encode()) * 8

    config_digest = _upload_blob(ecr, repository_name, config_bytes)
    layer_digest = _upload_blob(ecr, repository_name, layer_bytes)

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
    manifest_bytes = json.dumps(manifest, separators=(",", ":")).encode()
    return manifest_bytes, config_digest, layer_digest


def _push_image(ecr, repository_name: str, tag: str, salt: str | None = None):
    """Push a fully-formed, unique minimal image.

    Returns (image_digest, manifest_str, config_digest, layer_digest).
    """
    manifest_bytes, config_digest, layer_digest = _build_manifest(ecr, repository_name, salt)
    image_digest = _sha256_digest(manifest_bytes)
    manifest_str = manifest_bytes.decode()
    ecr.put_image(
        repositoryName=repository_name,
        imageManifest=manifest_str,
        imageManifestMediaType="application/vnd.docker.distribution.manifest.v2+json",
        imageTag=tag,
        imageDigest=image_digest,
    )
    return image_digest, manifest_str, config_digest, layer_digest


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
