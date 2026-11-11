"""mutable-repo-allows-tag-overwrite."""
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

CHECK = "mutable-repo-allows-tag-overwrite"
GROUP = 'image-tag-mutability'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """In a default MUTABLE repository, re-pushing an existing tag with different
    content succeeds, moves the tag to the new digest, and demotes the old digest
    to untagged."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name)
    first = _push_image(ecr, name, tag="v1", seed=b"content-a")
    first_digest = first["imageId"]["imageDigest"]

    second = _push_image(ecr, name, tag="v1", seed=b"content-b")
    second_digest = second["imageId"]["imageDigest"]
    assert second_digest != first_digest, (
        f"expected the re-push to yield a new digest distinct from {first_digest!r}, "
        f"got the same digest back: {second_digest!r}"
    )

    details = ecr.describe_images(repositoryName=name)["imageDetails"]
    by_digest = {d["imageDigest"]: d for d in details}
    second_tags = by_digest[second_digest].get("imageTags") or []
    assert "v1" in second_tags, (
        f"expected tag 'v1' to have moved onto the new digest {second_digest!r}, "
        f"but describe_images reports its tags as {second_tags!r}"
    )
    first_tags = by_digest.get(first_digest, {}).get("imageTags") or []
    assert "v1" not in first_tags, (
        f"expected the old digest {first_digest!r} to be demoted to untagged, "
        f"but describe_images still reports it tagged with {first_tags!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
