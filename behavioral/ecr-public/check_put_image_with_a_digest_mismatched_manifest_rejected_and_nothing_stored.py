"""put-image-with-a-digest-mismatched-manifest-rejected-and-nothing-stored."""
from __future__ import annotations

import hashlib
import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-image-with-a-digest-mismatched-manifest-rejected-and-nothing-stored"
GROUP = 'registry-data-plane'
SERVICES = ['ecr-public']

CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"
MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"

# Every byte pushed here is synthetic: an ECR Public repository is world-visible on
# gallery.ecr.aws for as long as it exists.


def _ecr_public(ctx):
    """ECR Public is a us-east-1-only API; other regions answer UnsupportedCommandException."""
    return ctx.client("ecr-public", region="us-east-1")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real-audit", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name, resp


def _error(fn) -> dict:
    """Call fn() and return the AWS Error (Code and Message); an unexpected success raises."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED with {resp!r}")


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repository_name, data: bytes) -> str:
    digest = _sha256_digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repository_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repository_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repository_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


def _build_manifest(config_digest, config_size, layer_digest, layer_size) -> str:
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": {"mediaType": CONFIG_MEDIA_TYPE, "size": config_size, "digest": config_digest},
        "layers": [{"mediaType": LAYER_MEDIA_TYPE, "size": layer_size, "digest": layer_digest}],
    }
    return json.dumps(manifest, separators=(",", ":"))


def _describe_all_images(ecr, repository_name):
    """Fully paginated DescribeImages."""
    details = []
    for page in ecr.get_paginator("describe_images").paginate(repositoryName=repository_name):
        details.extend(page["imageDetails"])
    return details


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """PutImage recomputes the manifest hash: a mismatched imageDigest fails with
    ImageDigestDoesNotMatchException and stores no image or tag, while the identical manifest with
    its true digest is accepted and describable."""
    ecr = _ecr_public(ctx)
    name, _ = _create_repository(ctx, ecr)

    config_bytes = json.dumps({"architecture": "amd64", "os": "linux", "repo": name}).encode()
    layer_bytes = b"sim2real-digest-mismatch-layer-" + name.encode() + bytes(range(48))
    config_digest = _upload_blob(ecr, name, config_bytes)
    layer_digest = _upload_blob(ecr, name, layer_bytes)
    manifest_str = _build_manifest(
        config_digest, len(config_bytes), layer_digest, len(layer_bytes)
    )
    true_digest = _sha256_digest(manifest_str.encode())

    # A well-formed sha256 of DIFFERENT content: format validation cannot be what refuses it.
    wrong_digest = _sha256_digest(b"not-the-manifest-body-" + name.encode())
    assert wrong_digest != true_digest and len(wrong_digest) == len(true_digest), (
        f"{wrong_digest!r} must be a well-formed sha256 distinct from {true_digest!r}"
    )

    error = _error(
        lambda: ecr.put_image(
            repositoryName=name,
            imageManifest=manifest_str,
            imageManifestMediaType=MANIFEST_MEDIA_TYPE,
            imageTag="mismatched",
            imageDigest=wrong_digest,
        )
    )
    assert error["Code"] == "ImageDigestDoesNotMatchException", (
        f"PutImage with a digest that is not the manifest's sha256 was answered {error!r}"
    )
    expected = (
        f"The image with digest '{wrong_digest}' in repository '{name}' and registry ID "
        f"'{ctx.account}' does not match the image digest that Amazon ECR has calculated."
    )
    assert error["Message"] == expected, f"refusal message {error['Message']!r} != {expected!r}"

    # --- the effect is ABSENT: no image under either digest, and no tag ---------------------------
    after_reject = _describe_all_images(ecr, name)
    assert after_reject == [], (
        f"the rejected PutImage stored something: {after_reject!r}"
    )
    tag_error = _error(
        lambda: ecr.describe_images(repositoryName=name, imageIds=[{"imageTag": "mismatched"}])
    )
    assert tag_error["Code"] == "ImageNotFoundException", (
        f"looking up the rejected push's tag answered {tag_error!r}, so a tag was created"
    )
    expected = (
        f"The image with imageId {{imageDigest:'null', imageTag:'mismatched'}} does not exist "
        f"within the repository with name '{name}' in the registry with id '{ctx.account}'"
    )
    assert tag_error["Message"] == expected, f"{tag_error['Message']!r} != {expected!r}"
    wrong_digest_error = _error(
        lambda: ecr.describe_images(repositoryName=name, imageIds=[{"imageDigest": wrong_digest}])
    )
    assert wrong_digest_error["Code"] == "ImageNotFoundException", (
        f"the manifest was stored under the CLAIMED digest: {wrong_digest_error!r}"
    )
    expected = (
        f"The image with imageId {{imageDigest:'{wrong_digest}', imageTag:'null'}} does not exist "
        f"within the repository with name '{name}' in the registry with id '{ctx.account}'"
    )
    assert wrong_digest_error["Message"] == expected, (
        f"{wrong_digest_error['Message']!r} != {expected!r}"
    )

    # --- POSITIVE CONTROL: the identical manifest with its true digest is accepted -----------------
    control = ecr.put_image(
        repositoryName=name,
        imageManifest=manifest_str,
        imageManifestMediaType=MANIFEST_MEDIA_TYPE,
        imageTag="mismatched",
        imageDigest=true_digest,
    )["image"]
    assert control["imageId"]["imageDigest"] == true_digest, (
        f"the control push stored {control['imageId']['imageDigest']!r}, not {true_digest!r}"
    )
    assert control["imageId"]["imageTag"] == "mismatched", f"{control['imageId']!r}"

    described = _describe_all_images(ecr, name)
    assert [detail["imageDigest"] for detail in described] == [true_digest], (
        f"after the control push the repository holds "
        f"{[detail['imageDigest'] for detail in described]!r}, expected exactly {[true_digest]!r}"
    )
    assert described[0].get("imageTags") == ["mismatched"], (
        f"the control image's tags read {described[0].get('imageTags')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
