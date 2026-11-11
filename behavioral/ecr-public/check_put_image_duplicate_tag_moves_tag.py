"""put-image-duplicate-tag-moves-tag."""
from __future__ import annotations

import hashlib
import json

from behavioral_harness import tags

CHECK = "put-image-duplicate-tag-moves-tag"
GROUP = 'image-data-plane'
SERVICES = ['ecr-public']

CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"
MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name, resp


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repository_name, data: bytes) -> str:
    """Initiate -> UploadPart -> Complete for a single blob; return its sha256 digest."""
    digest = _sha256_digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repository_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repository_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repository_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


def _build_manifest(config_digest, config_size, layer_digest, layer_size) -> str:
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": {"mediaType": CONFIG_MEDIA_TYPE, "size": config_size, "digest": config_digest},
        "layers": [
            {"mediaType": LAYER_MEDIA_TYPE, "size": layer_size, "digest": layer_digest}
        ],
    }
    return json.dumps(manifest, separators=(",", ":"))


def _push_test_image(ecr, repository_name, tag, seed: bytes = b""):
    """Full data-plane push: upload a config blob + a layer blob, build a valid v2 manifest
    referencing both, then PutImage with the tag. Returns (manifest_str, manifest_digest, resp)."""
    config_bytes = json.dumps(
        {"architecture": "amd64", "os": "linux", "seed": seed.hex()}
    ).encode()
    layer_bytes = b"behavioral-fidelity-layer-" + seed + bytes(range(32))
    config_digest = _upload_blob(ecr, repository_name, config_bytes)
    layer_digest = _upload_blob(ecr, repository_name, layer_bytes)
    manifest_str = _build_manifest(
        config_digest, len(config_bytes), layer_digest, len(layer_bytes)
    )
    manifest_digest = _sha256_digest(manifest_str.encode())
    resp = ecr.put_image(
        repositoryName=repository_name,
        imageManifest=manifest_str,
        imageManifestMediaType=MANIFEST_MEDIA_TYPE,
        imageTag=tag,
    )
    return manifest_str, manifest_digest, resp


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ECR Public image tags are MUTABLE: PutImage reusing an existing imageTag for a
    different manifest succeeds and *moves* the tag to the new digest, leaving the
    previously-tagged image present but untagged (no ImageTagAlreadyExistsException).
    """
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(
        ctx, ecr, tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    tag = "stable"

    _, first_digest, _ = _push_test_image(ecr, name, tag, seed=b"first")

    # Build and push a second, different manifest under the same tag.
    config_bytes = b'{"seed":"second"}'
    layer_bytes = b"different-layer-content-for-conflict-test" + bytes(range(8))
    config_digest = _upload_blob(ecr, name, config_bytes)
    layer_digest = _upload_blob(ecr, name, layer_bytes)
    manifest_str = _build_manifest(config_digest, len(config_bytes), layer_digest, len(layer_bytes))

    resp = ecr.put_image(
        repositoryName=name,
        imageManifest=manifest_str,
        imageManifestMediaType="application/vnd.docker.distribution.manifest.v2+json",
        imageTag=tag,
    )
    second_digest = resp["image"]["imageId"]["imageDigest"]
    assert second_digest != first_digest, "second manifest unexpectedly had the same digest"

    # The tag now resolves to the NEW digest.
    tags_resp = ecr.describe_image_tags(repositoryName=name)
    tag_entries = {t["imageTag"]: t["imageDetail"]["imageDigest"] for t in tags_resp["imageTagDetails"]}
    assert tag_entries.get(tag) == second_digest, (
        f"tag {tag!r} should have moved to {second_digest}, got {tag_entries}"
    )

    # Both manifests still exist; the original is now untagged.
    described = ecr.describe_images(repositoryName=name)["imageDetails"]
    digests = {d["imageDigest"] for d in described}
    assert first_digest in digests, f"original image disappeared: {digests}"
    assert second_digest in digests, f"new image missing: {digests}"

    first_detail = next(d for d in described if d["imageDigest"] == first_digest)
    assert tag not in first_detail.get("imageTags", []), (
        f"tag {tag!r} should no longer be on the original image: {first_detail.get('imageTags')}"
    )

    ecr.delete_repository(repositoryName=name, force=True)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
