"""immutable-tag-mutability-blocks-retag."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target accepting a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": "immutable-tag-mutability-blocks-retag"}], **kwargs
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

CHECK = "immutable-tag-mutability-blocks-retag"
GROUP = 'overly-permissive'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """In an IMMUTABLE repository, re-pushing an existing tag with different content fails with
    ImageTagAlreadyExistsException and the tag keeps its original digest, while pushing a new
    tag still succeeds (positive control)."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name, imageTagMutability="IMMUTABLE")
    first = _push_image(ecr, name, tag="v1", seed=b"first-content")
    first_digest = first["imageId"]["imageDigest"]

    code, message = _error(lambda: _push_image(ecr, name, tag="v1", seed=b"second-different-content"))
    assert code == "ImageTagAlreadyExistsException", f"expected ImageTagAlreadyExistsException, got {code}"
    assert message == (
        f"The image tag 'v1' already exists in the '{name}' repository and cannot be overwritten because the tag is immutable."
    ), message

    # Effect absent: an independent read (DescribeImages, not the rejected PutImage's own
    # response) shows tag v1 still resolves to the ORIGINAL digest -- it did not silently move.
    still = ecr.describe_images(repositoryName=name, imageIds=[{"imageTag": "v1"}])["imageDetails"]
    assert still[0]["imageDigest"] == first_digest, (
        f"tag v1 moved to {still[0]['imageDigest']!r} despite the refused re-push; expected it to "
        f"still resolve to the original digest {first_digest!r}"
    )

    # Positive control: a new tag must still push. Its seed differs from both prior pushes
    # because the rejected retag's layer upload persisted, so reusing it would raise
    # LayerAlreadyExistsException on CompleteLayerUpload.
    second = _push_image(ecr, name, tag="v2", seed=b"third-new-tag-content")
    second_digest = second["imageId"]["imageDigest"]
    assert second_digest != first_digest, "v2 minted the same digest as v1, so it proves nothing new"
    still_v2 = ecr.describe_images(repositoryName=name, imageIds=[{"imageTag": "v2"}])["imageDetails"]
    assert still_v2[0]["imageDigest"] == second_digest, (
        f"tag v2 resolves to {still_v2[0]['imageDigest']!r}, not the digest {second_digest!r} PutImage "
        f"reported for it"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
