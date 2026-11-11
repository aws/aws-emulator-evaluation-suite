"""batch-delete-image-partial-outcome."""
from __future__ import annotations

import hashlib
import json

from behavioral_harness import tags

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
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

CHECK = "batch-delete-image-partial-outcome"
GROUP = 'image-data-plane'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDeleteImage with a mix of valid and bogus imageIds deletes the valid one
    and reports a per-entry failure for the bogus one (partial success, not all-or-nothing)."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name)
    image = _push_image(ecr, name, tag="to-delete", seed=b"delete-me")
    digest = image["imageId"]["imageDigest"]
    bogus_digest = "sha256:" + ("0" * 64)

    resp = ecr.batch_delete_image(
        repositoryName=name,
        imageIds=[{"imageDigest": digest}, {"imageDigest": bogus_digest}],
    )
    deleted_digests = {i["imageDigest"] for i in resp["imageIds"]}
    assert deleted_digests == {digest}, (
        f"expected exactly {{{digest!r}}} reported deleted, got {deleted_digests!r}"
    )

    failures = resp["failures"]
    assert len(failures) == 1, f"expected exactly one failure entry, got {failures!r}"
    bogus_failure = failures[0]
    assert bogus_failure["imageId"]["imageDigest"] == bogus_digest, (
        f"expected the failure to name the bogus digest {bogus_digest!r}, "
        f"got {bogus_failure['imageId']!r}"
    )
    assert bogus_failure["failureCode"] == "ImageNotFound", (
        f"expected failureCode 'ImageNotFound' for a nonexistent digest, "
        f"got {bogus_failure['failureCode']!r}"
    )

    remaining = {i["imageDigest"] for i in ecr.list_images(repositoryName=name)["imageIds"]}
    assert digest not in remaining, (
        f"deleted digest {digest!r} is still listed by ListImages: {remaining!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
