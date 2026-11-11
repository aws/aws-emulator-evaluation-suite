"""push-untagged-then-multi-tag."""
from __future__ import annotations

import hashlib
import json

from behavioral_harness import tags

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]

def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

def _upload_layer(ecr, repo_name, data):
    """InitiateLayerUpload -> UploadLayerPart -> CompleteLayerUpload; returns (digest, size)."""
    digest = _sha256_digest(data)
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

def _build_manifest(layer_digest, layer_size, config_digest, config_size):
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
    return json.dumps(manifest)

def _push_image(ecr, repo_name, tag=None, seed=b"layer-data"):
    """Push a minimally valid Docker Schema-2 image; returns the image dict from PutImage."""
    layer_digest, layer_size = _upload_layer(ecr, repo_name, seed)
    config_seed = b'{"architecture":"amd64","config":{},"seed":"' + seed + b'"}'
    config_digest, config_size = _upload_layer(ecr, repo_name, config_seed)
    manifest_str = _build_manifest(layer_digest, layer_size, config_digest, config_size)
    kwargs = {"repositoryName": repo_name, "imageManifest": manifest_str}
    if tag:
        kwargs["imageTag"] = tag
    return ecr.put_image(**kwargs)["image"]

CHECK = "push-untagged-then-multi-tag"
GROUP = 'image-data-plane'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The same image digest can carry multiple simultaneous tags: tagging an
    untagged image twice with distinct tags leaves both tags resolving to the
    one image, rather than the second tag replacing the first."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name, tags=[{"Key": "sim2real", "Value": CHECK}])
    image = _push_image(ecr, name, tag=None, seed=b"shared-content")
    digest = image["imageId"]["imageDigest"]
    manifest = image["imageManifest"]

    second = ecr.put_image(
        repositoryName=name, imageManifest=manifest, imageTag="alias"
    )["image"]
    assert second["imageId"]["imageDigest"] == digest, (
        f"tagging the existing manifest with 'alias' produced digest "
        f"{second['imageId']['imageDigest']}, expected the original {digest}"
    )

    third = ecr.put_image(
        repositoryName=name, imageManifest=manifest, imageTag="alias-two"
    )["image"]
    assert third["imageId"]["imageDigest"] == digest, (
        f"tagging the same manifest with 'alias-two' produced digest "
        f"{third['imageId']['imageDigest']}, expected the original {digest}"
    )

    details = ecr.describe_images(repositoryName=name, imageIds=[{"imageDigest": digest}])[
        "imageDetails"
    ]
    assert len(details) == 1, (
        f"expected exactly one image entry for digest {digest}, got {len(details)}: {details}"
    )
    tag_set = set(details[0].get("imageTags") or [])
    assert tag_set == {"alias", "alias-two"}, (
        f"expected digest {digest} to carry both tags, got {tag_set}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
