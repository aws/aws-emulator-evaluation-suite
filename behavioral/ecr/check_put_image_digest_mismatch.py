"""put-image-digest-mismatch."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository name."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name

def _upload_layer(ecr, repo_name, data):
    """InitiateLayerUpload -> UploadLayerPart -> CompleteLayerUpload; returns (digest, size)."""
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
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

def _build_manifest(layer_digest, layer_size):
    """Builds a manifest referencing layer_digest for both config and layer, and returns
    (manifest_str, the manifest's OWN sha256 digest as ECR computes it for PutImage)."""
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": layer_size,
            "digest": layer_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": layer_size,
                "digest": layer_digest,
            }
        ],
    }
    manifest_str = json.dumps(manifest)
    correct_digest = "sha256:" + hashlib.sha256(manifest_str.encode()).hexdigest()
    return manifest_str, correct_digest

CHECK = "put-image-digest-mismatch"
GROUP = 'error-semantics'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutImage with an imageDigest that is not the manifest's sha256 is refused
    ImageDigestDoesNotMatchException with the exact message and leaves no tag, while the same
    call with the correct digest succeeds and BatchGetImage returns it."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = _create_repo(ecr, ctx)
    layer_digest, layer_size = _upload_layer(ecr, name, b"digest-mismatch-content")
    manifest_str, correct_digest = _build_manifest(layer_digest, layer_size)
    wrong_digest = "sha256:" + ("b" * 64)
    assert wrong_digest != correct_digest, f"test setup produced no mismatch: both are {correct_digest}"

    # Positive control: PutImage on this repo, with the correct digest, works before we break anything.
    control = ecr.put_image(
        repositoryName=name, imageManifest=manifest_str, imageDigest=correct_digest, imageTag="control",
    )
    assert control["image"]["imageId"]["imageDigest"] == correct_digest, (
        f"positive control failed: expected digest {correct_digest}, got {control['image']['imageId']}"
    )

    # Break exactly one thing: supply a digest that does not match the manifest's own hash.
    try:
        ecr.put_image(
            repositoryName=name, imageManifest=manifest_str, imageDigest=wrong_digest, imageTag="v1",
        )
        raise AssertionError("put_image with a mismatched imageDigest unexpectedly succeeded")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "ImageDigestDoesNotMatchException", f"expected ImageDigestDoesNotMatchException, got {code}"
        message = exc.response.get("Error", {}).get("Message")
        expected_message = (
            f"The image with digest '{wrong_digest}' in repository '{name}' and registry ID "
            f"'{account_id}' does not match the image digest that Amazon ECR has calculated."
        )
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: an independent read shows the rejected push created nothing under "v1".
    existing_tags = {img.get("imageTag") for img in ecr.list_images(repositoryName=name)["imageIds"]}
    assert "v1" not in existing_tags, f"rejected push is visible in list_images: {existing_tags}"

    # Restore: the identical call, corrected, now succeeds.
    restored = ecr.put_image(
        repositoryName=name, imageManifest=manifest_str, imageDigest=correct_digest, imageTag="v1",
    )
    assert restored["image"]["imageId"]["imageDigest"] == correct_digest, (
        f"restored push has mismatched digest: {restored['image']['imageId']}"
    )

    # Terminal read, independent of the mutating call: the corrected image is visible at the destination.
    fetched = ecr.batch_get_image(repositoryName=name, imageIds=[{"imageTag": "v1"}])
    assert len(fetched["images"]) == 1, f"expected exactly one image for tag v1, got {fetched}"
    assert fetched["images"][0]["imageId"]["imageDigest"] == correct_digest, (
        f"batch_get_image returned wrong digest: {fetched['images'][0]['imageId']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
