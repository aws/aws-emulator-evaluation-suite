"""server-side-manifest-schema-validation-enforced."""
from __future__ import annotations

import gzip
import hashlib
import json
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-manifest-schema-validation-enforced"
GROUP = "server-side"
SERVICES = ["ecr-public"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutImage rejects a manifest whose embedded mediaType says manifest LIST but whose body is a
    single-image manifest, creating no image; the same body declared as single-image is accepted."""
    ecrp = _regional_client(ctx, "ecr-public")
    repo_name = ctx.unique_name("sim2real-behav-manifest-")
    ecrp.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": "audit"}])
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=repo_name, force=True))

    config_bytes = json.dumps({"architecture": "amd64", "os": "linux", "config": {}}).encode()
    layer_bytes = gzip.compress(b"sim2real-behav-layer-content")

    config_digest = _upload_blob(ecrp, repo_name, config_bytes)
    layer_digest = _upload_blob(ecrp, repo_name, layer_bytes)

    def _manifest(declared_media_type: str) -> str:
        # "config"/"layers" are single-image manifest fields; a manifest LIST instead
        # requires a "manifests" array and has neither "config" nor "layers" at all.
        return json.dumps(
            {
                "schemaVersion": 2,
                "mediaType": declared_media_type,
                "config": {
                    "mediaType": "application/vnd.docker.container.image.v1+json",
                    "size": len(config_bytes),
                    "digest": config_digest,
                },
                "layers": [
                    {
                        "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                        "size": len(layer_bytes),
                        "digest": layer_digest,
                    }
                ],
            }
        )

    # No client-side imageManifestMediaType is sent, so only the embedded mediaType conflicts.
    bad_manifest_text = _manifest("application/vnd.docker.distribution.manifest.list.v2+json")
    bad_tag = ctx.unique_name("sim2real-behav-bad-")[:120]
    err = _error(
        lambda: ecrp.put_image(repositoryName=repo_name, imageManifest=bad_manifest_text, imageTag=bad_tag)
    )
    expected = ("InvalidParameterException", "Invalid parameter at 'ImageManifest' failed to satisfy constraint: 'Invalid JSON syntax'")
    assert (err.get("Code"), err.get("Message")) == expected, f"expected {expected}, got {err}"

    tag_err = _error(
        lambda: ecrp.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": bad_tag}])
    )
    expected = (
        "ImageNotFoundException",
        f"The image with imageId {{imageDigest:'null', imageTag:'{bad_tag}'}} does not exist within the "
        f"repository with name '{repo_name}' in the registry with id '{ctx.account}'",
    )
    assert (tag_err.get("Code"), tag_err.get("Message")) == expected, (
        f"expected no image under rejected tag {expected}, got {tag_err}"
    )

    good_manifest_text = _manifest("application/vnd.docker.distribution.manifest.v2+json")
    good_tag = ctx.unique_name("sim2real-behav-good-")[:120]
    put_resp = ecrp.put_image(repositoryName=repo_name, imageManifest=good_manifest_text, imageTag=good_tag)
    assert put_resp["image"]["imageId"]["imageTag"] == good_tag, (
        f"expected put_image to echo tag {good_tag!r}, got {put_resp['image']['imageId']}"
    )

    described = ecrp.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": good_tag}])
    assert len(described["imageDetails"]) == 1, (
        f"expected exactly 1 image under tag {good_tag!r}, got {described['imageDetails']}"
    )
    actual_media_type = described["imageDetails"][0]["imageManifestMediaType"]
    assert actual_media_type == "application/vnd.docker.distribution.manifest.v2+json", (
        f"expected imageManifestMediaType application/vnd.docker.distribution.manifest.v2+json, "
        f"got {actual_media_type}"
    )


def _upload_blob(ecrp: Any, repo_name: str, content: bytes) -> str:
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    upload_id = ecrp.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecrp.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(content) - 1,
        layerPartBlob=content,
    )
    ecrp.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest


def _error(fn: Callable[[], Any]) -> dict:
    """Return the botocore Error dict from fn(); raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _regional_client(ctx, service: str, region: str = "us-east-1"):
    """ecr-public is served only from us-east-1, so pin that region."""
    from botocore.config import Config

    return ctx.client(service, region=region, config=Config(retries={"max_attempts": 8, "mode": "standard"}))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
