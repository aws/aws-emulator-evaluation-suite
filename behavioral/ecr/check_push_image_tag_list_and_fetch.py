"""push-image-tag-list-and-fetch."""
from __future__ import annotations

import hashlib
import json

from behavioral_harness import tags

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name,
        tags=[{"Key": "sim2real", "Value": "push-image-tag-list-and-fetch"}],
        **kwargs,
    )
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

CHECK = "push-image-tag-list-and-fetch"
GROUP = 'image-data-plane'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pushed, tagged image is visible via ListImages/DescribeImages and its exact
    manifest bytes are retrievable via BatchGetImage (round-trip integrity)."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name)
    image = _push_image(ecr, name, tag="v1", seed=b"payload-1")
    digest = image["imageId"]["imageDigest"]

    image_ids = ecr.list_images(repositoryName=name)["imageIds"]
    assert any(i.get("imageTag") == "v1" and i["imageDigest"] == digest for i in image_ids), (
        f"ListImages does not reflect the pushed tag 'v1' at digest {digest!r}: {image_ids!r}"
    )

    details = ecr.describe_images(repositoryName=name)["imageDetails"]
    match = next(d for d in details if d["imageDigest"] == digest)
    assert "v1" in (match.get("imageTags") or []), (
        f"DescribeImages reports tags {match.get('imageTags')!r} for digest {digest!r}, "
        f"expected 'v1' among them"
    )

    got = ecr.batch_get_image(repositoryName=name, imageIds=[{"imageDigest": digest}])
    assert len(got["images"]) == 1, (
        f"BatchGetImage returned {len(got['images'])} images for digest {digest!r}, expected 1"
    )
    assert got["images"][0]["imageManifest"] == image["imageManifest"], (
        "BatchGetImage returned different manifest bytes than PutImage accepted: "
        f"{got['images'][0]['imageManifest'][:300]!r} vs {image['imageManifest'][:300]!r}"
    )
    assert got["images"][0]["imageId"]["imageDigest"] == digest, (
        f"BatchGetImage returned digest {got['images'][0]['imageId']['imageDigest']!r}, "
        f"expected {digest!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
