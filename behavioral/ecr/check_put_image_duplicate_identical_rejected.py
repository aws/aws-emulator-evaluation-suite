"""put-image-duplicate-identical-rejected."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises,
    so a target accepting a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    kwargs.setdefault("tags", [{"Key": "sim2real", "Value": CHECK}])
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

CHECK = "put-image-duplicate-identical-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Re-pushing a byte-identical manifest under the same tag raises ImageAlreadyExistsException
    and creates no duplicate, while a different manifest pushed to that mutable tag succeeds."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name)
    image = _push_image(ecr, name, tag="v1", seed=b"identical-content")
    manifest = image["imageManifest"]
    digest_a = image["imageId"]["imageDigest"]

    code, message = _error_code(
        lambda: ecr.put_image(
            repositoryName=name, imageManifest=manifest, imageTag="v1"
        )
    )
    assert code == "ImageAlreadyExistsException", (
        f"expected ImageAlreadyExistsException, got {code}"
    )
    expected_message = (
        f"Image with digest '{digest_a}' and tag 'v1' already exists in the repository with "
        f"name '{name}' in registry with id '{account_id}'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the rejected re-push created no duplicate — the tag still resolves
    # to exactly one image, at the original digest, via an independent read.
    details = ecr.describe_images(repositoryName=name, imageIds=[{"imageTag": "v1"}])["imageDetails"]
    assert len(details) == 1 and details[0]["imageDigest"] == digest_a, (
        f"expected exactly one image at {digest_a}, got {details!r}"
    )

    # positive control on the same wiring: this is a MUTABLE (default) repository, so a
    # genuinely different manifest pushed to the same tag must still succeed — proving the
    # rejection above is specific to identical content, not a general lock on re-pushing v1.
    image_b = _push_image(ecr, name, tag="v1", seed=b"distinct-content")
    digest_b = image_b["imageId"]["imageDigest"]
    assert digest_b != digest_a, "the differentiator push must produce a distinct digest"

    details_after = ecr.describe_images(repositoryName=name, imageIds=[{"imageTag": "v1"}])["imageDetails"]
    assert len(details_after) == 1 and details_after[0]["imageDigest"] == digest_b, (
        f"expected v1 to now resolve to the overwritten digest {digest_b}, got {details_after!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
