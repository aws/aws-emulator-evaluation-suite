"""put-image-tag-mutability-transition."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name,
        tags=[{"Key": "sim2real", "Value": CHECK}],
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

def _digest_for_tag(ecr, repo_name, tag):
    """Read the tag->digest mapping via DescribeImages rather than PutImage's response."""
    details = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": tag}])["imageDetails"]
    assert len(details) == 1, f"expected exactly one image for tag {tag!r}, got {len(details)}"
    return details[0]["imageDigest"]

CHECK = "put-image-tag-mutability-transition"
GROUP = 'image-tag-mutability'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutImageTagMutability changes are reflected in DescribeRepositories and enforced both ways:
    a tag overwrite that succeeds while MUTABLE is refused once IMMUTABLE (digest untouched),
    and succeeds again once switched back."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ecr, ctx)
    name = repo["repositoryName"]
    assert repo["imageTagMutability"] == "MUTABLE", (
        f"expected a freshly created repository to default to MUTABLE, got {repo['imageTagMutability']!r}"
    )

    # Positive control while MUTABLE: overwriting an existing tag with new content succeeds
    # and moves the digest — this is what the IMMUTABLE transition below must then block.
    first = _push_image(ecr, name, tag="v1", seed=b"content-x")
    second = _push_image(ecr, name, tag="v1", seed=b"content-y")
    assert second["imageId"]["imageDigest"] != first["imageId"]["imageDigest"], (
        "expected overwriting tag v1 while MUTABLE to move the digest, but it did not change"
    )
    assert _digest_for_tag(ecr, name, "v1") == second["imageId"]["imageDigest"], (
        "expected an independent DescribeImages read to reflect the MUTABLE overwrite"
    )

    resp = ecr.put_image_tag_mutability(repositoryName=name, imageTagMutability="IMMUTABLE")
    assert resp["imageTagMutability"] == "IMMUTABLE", f"put response did not echo IMMUTABLE: {resp}"
    described = ecr.describe_repositories(repositoryNames=[name])["repositories"][0]
    assert described["imageTagMutability"] == "IMMUTABLE", (
        f"expected DescribeRepositories to reflect IMMUTABLE, got {described['imageTagMutability']!r}"
    )

    # Negative: the identical kind of overwrite that just succeeded is now refused.
    code, message = _error_code(lambda: _push_image(ecr, name, tag="v1", seed=b"content-z"))
    assert code == "ImageTagAlreadyExistsException", f"expected ImageTagAlreadyExistsException, got {code}"
    expected_message = (
        f"The image tag 'v1' already exists in the '{name}' repository and cannot be overwritten "
        f"because the tag is immutable."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: tag v1 still points at the last successful (MUTABLE) digest.
    assert _digest_for_tag(ecr, name, "v1") == second["imageId"]["imageDigest"], (
        "expected the rejected IMMUTABLE overwrite to leave tag v1 pointing at the prior digest"
    )

    # Restore + identical call succeeds again: the transition is live and bidirectional.
    ecr.put_image_tag_mutability(repositoryName=name, imageTagMutability="MUTABLE")
    third = _push_image(ecr, name, tag="v1", seed=b"content-w")
    assert third["imageId"]["imageDigest"] != second["imageId"]["imageDigest"], (
        "expected the restored MUTABLE overwrite to move the digest again"
    )
    assert _digest_for_tag(ecr, name, "v1") == third["imageId"]["imageDigest"], (
        "expected an independent DescribeImages read to reflect the restored MUTABLE overwrite"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
