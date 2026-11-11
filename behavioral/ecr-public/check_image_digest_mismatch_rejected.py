"""image-digest-mismatch-rejected."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-digest-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr-public"]

CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"
MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutImage with an imageDigest that is not the manifest's sha256 is refused
    ImageDigestDoesNotMatchException with the exact message and leaves no image under the tag or
    the claimed digest, while the same manifest with its true digest is accepted and described."""
    # ECR Public is a us-east-1-ONLY API (other regions answer UnsupportedCommandException).
    ecr = ctx.client("ecr-public", region="us-east-1")
    name = ctx.unique_name("sim2real-behav-ecrp-digestmismatch-")
    ecr.create_repository(repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _force_delete_repository(ecr, name))

    manifest_str, _config_digest, _layer_digest = _build_manifest(ecr, name)
    true_digest = _sha256_digest(manifest_str.encode())
    wrong_digest = _sha256_digest(b"not-the-real-manifest-body-" + name.encode())
    assert wrong_digest != true_digest, "the wrong digest must differ from the manifest's true digest"

    code, code_msg = _error_code(
        lambda: ecr.put_image(
            repositoryName=name,
            imageManifest=manifest_str,
            imageManifestMediaType=MANIFEST_MEDIA_TYPE,
            imageTag="broken",
            imageDigest=wrong_digest,
        )
    )
    assert code == "ImageDigestDoesNotMatchException", (
        f"expected ImageDigestDoesNotMatchException, got {code!r}"
    )
    expected_code_msg = f"The image with digest '{wrong_digest}' in repository '{name}' and registry ID '{ctx.account}' does not match the image digest that Amazon ECR has calculated."
    assert code_msg == expected_code_msg, f"expected message {expected_code_msg!r}, got {code_msg!r}"

    # --- the effect is ABSENT: independent reads at the destination, by tag and by the claimed digest
    tag_code, tag_code_msg = _error_code(
        lambda: ecr.describe_images(repositoryName=name, imageIds=[{"imageTag": "broken"}])
    )
    assert tag_code == "ImageNotFoundException", (
        f"looking up the rejected push's tag answered {tag_code!r}, so a tag was created"
    )
    expected_tag_code_msg = f"The image with imageId {{imageDigest:'null', imageTag:'broken'}} does not exist within the repository with name '{name}' in the registry with id '{ctx.account}'"
    assert tag_code_msg == expected_tag_code_msg, f"expected message {expected_tag_code_msg!r}, got {tag_code_msg!r}"
    claimed_digest_code, claimed_digest_code_msg = _error_code(
        lambda: ecr.describe_images(repositoryName=name, imageIds=[{"imageDigest": wrong_digest}])
    )
    assert claimed_digest_code == "ImageNotFoundException", (
        f"the manifest was stored under the CLAIMED digest: {claimed_digest_code!r}"
    )
    expected_claimed_digest_code_msg = f"The image with imageId {{imageDigest:'{wrong_digest}', imageTag:'null'}} does not exist within the repository with name '{name}' in the registry with id '{ctx.account}'"
    assert claimed_digest_code_msg == expected_claimed_digest_code_msg, f"expected message {expected_claimed_digest_code_msg!r}, got {claimed_digest_code_msg!r}"

    # --- RESTORE: the identical call with its TRUE digest succeeds (the required positive control) --
    control = ecr.put_image(
        repositoryName=name,
        imageManifest=manifest_str,
        imageManifestMediaType=MANIFEST_MEDIA_TYPE,
        imageTag="broken",
        imageDigest=true_digest,
    )["image"]
    assert control["imageId"]["imageDigest"] == true_digest, (
        f"the control push stored {control['imageId']['imageDigest']!r}, not {true_digest!r}"
    )
    described = ecr.describe_images(repositoryName=name, imageIds=[{"imageTag": "broken"}])[
        "imageDetails"
    ]
    assert [detail["imageDigest"] for detail in described] == [true_digest], (
        f"after the control push the repository holds "
        f"{[detail['imageDigest'] for detail in described]!r}, expected exactly {[true_digest]!r}"
    )


def _error_code(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED with {resp!r}")


def _force_delete_repository(ecr, name: str) -> None:
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repository_name: str, blob: bytes) -> str:
    """Full initiate -> upload-part -> complete layer-upload cycle for one blob."""
    digest = _sha256_digest(blob)
    upload_id = ecr.initiate_layer_upload(repositoryName=repository_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repository_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob) - 1,
        layerPartBlob=blob,
    )
    ecr.complete_layer_upload(
        repositoryName=repository_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


def _build_manifest(ecr, repository_name: str):
    """Upload a config blob + a layer blob; return (manifest_str, config_digest, layer_digest)."""
    config_bytes = json.dumps({"architecture": "amd64", "os": "linux"}).encode()
    layer_bytes = b"sim2real-digest-mismatch-layer-" + repository_name.encode() + bytes(range(32))

    config_digest = _upload_blob(ecr, repository_name, config_bytes)
    layer_digest = _upload_blob(ecr, repository_name, layer_bytes)

    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": {
            "mediaType": CONFIG_MEDIA_TYPE,
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": LAYER_MEDIA_TYPE,
                "size": len(layer_bytes),
                "digest": layer_digest,
            }
        ],
    }
    manifest_str = json.dumps(manifest, separators=(",", ":"))
    return manifest_str, config_digest, layer_digest


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
