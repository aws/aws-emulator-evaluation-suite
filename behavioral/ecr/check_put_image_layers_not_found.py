"""put-image-layers-not-found."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]

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

CHECK = "put-image-layers-not-found"
GROUP = 'error-semantics'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutImage naming a never-uploaded layer is refused LayersNotFoundException with the exact
    message and leaves no image or tag (ImageNotFoundException); after the layer is uploaded the
    identical manifest is accepted under v1."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name)

    # Positive control: a real, fully-uploaded image pushes cleanly.
    layer_digest, layer_size = _upload_layer(ecr, name, b"sim2real-put-image-layers-not-found-baseline-layer")
    config_digest, config_size = _upload_layer(
        ecr, name, b'{"architecture":"amd64","os":"linux","config":{}}'
    )
    baseline_manifest = _build_manifest(layer_digest, layer_size, config_digest, config_size)
    ecr.put_image(repositoryName=name, imageManifest=baseline_manifest, imageTag="baseline")
    baseline = {i["imageDigest"] for i in ecr.list_images(repositoryName=name)["imageIds"]}
    assert len(baseline) == 1, f"positive control did not land, got {sorted(baseline)}"

    # Break exactly one thing: the layer digest names a blob that was never uploaded.
    missing_bytes = b"sim2real-put-image-layers-not-found-never-uploaded-blob"
    missing_digest = _sha256_digest(missing_bytes)
    bad_manifest = _build_manifest(missing_digest, len(missing_bytes), config_digest, config_size)

    code, message = _error_code(
        lambda: ecr.put_image(repositoryName=name, imageManifest=bad_manifest, imageTag="v1")
    )
    assert code == "LayersNotFoundException", f"expected LayersNotFoundException, got {code}"
    expected_message = (
        f"Layers with digests '[{missing_digest}]' required for pushing image into repository "
        f"with name '{name}' in the registry with id '{account_id}' do not exist"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no new digest in ListImages, and the attempted tag stays unbound.
    after_reject = {i["imageDigest"] for i in ecr.list_images(repositoryName=name)["imageIds"]}
    assert after_reject == baseline, f"rejected push left state behind: ListImages is now {sorted(after_reject)}"
    tag_code, tag_message = _error_code(
        lambda: ecr.describe_images(repositoryName=name, imageIds=[{"imageTag": "v1"}])
    )
    assert tag_code == "ImageNotFoundException", (
        f"tag 'v1' resolves after a rejected push (DescribeImages returned {tag_code!r})"
    )
    expected_tag_message = (
        f"The image with imageId {{imageDigest:'null', imageTag:'v1'}} does not exist within "
        f"the repository with name '{name}' in the registry with id '{account_id}'"
    )
    assert tag_message == expected_tag_message, f"expected message {expected_tag_message!r}, got {tag_message!r}"

    # Restore: upload the previously-missing layer for real, then retry the IDENTICAL
    # manifest -- it must now succeed.
    real_digest, real_size = _upload_layer(ecr, name, missing_bytes)
    assert (real_digest, real_size) == (missing_digest, len(missing_bytes)), (
        f"expected {missing_digest}/{len(missing_bytes)}, uploaded {real_digest}/{real_size}"
    )
    image = ecr.put_image(repositoryName=name, imageManifest=bad_manifest, imageTag="v1")["image"]
    assert image["imageId"]["imageTag"] == "v1", f"restored push echoed {image['imageId']}"

    final = {i["imageDigest"] for i in ecr.list_images(repositoryName=name)["imageIds"]}
    assert final == baseline | {image["imageId"]["imageDigest"]}, (
        f"after the restored push ListImages is {sorted(final)}, expected baseline plus the new digest"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
