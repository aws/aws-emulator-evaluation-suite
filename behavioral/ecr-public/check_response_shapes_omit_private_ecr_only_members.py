"""response-shapes-omit-private-ecr-only-members."""
from __future__ import annotations

import hashlib
import json

from behavioral_harness import tags

CHECK = "response-shapes-omit-private-ecr-only-members"
GROUP = 'overly-permissive'
SERVICES = ['ecr-public']

# Exact member sets from the ecr-public Smithy model (2020-10-30).
_REPOSITORY = {"repositoryArn", "registryId", "repositoryName", "repositoryUri", "createdAt"}
_IMAGE_DETAIL = {
    "registryId", "repositoryName", "imageDigest", "imageTags", "imageSizeInBytes",
    "imagePushedAt", "imageManifestMediaType", "artifactMediaType",
}
_REFERENCED_IMAGE_DETAIL = {
    "imageDigest", "imageSizeInBytes", "imagePushedAt", "imageManifestMediaType",
    "artifactMediaType",
}
_IMAGE_TAG_DETAIL = {"imageTag", "createdAt", "imageDetail"}

# The private-ECR (2015-09-21) members that ECR Public deliberately does NOT model, because the
# corresponding features do not exist in the public registry. Named explicitly so a failure says
# *which* private-ECR feature is being reported, not merely "extra key".
_PRIVATE_ONLY_IMAGE_DETAIL = {
    "imageScanStatus",            # no image scanning in ECR Public
    "imageScanFindingsSummary",   # no image scanning in ECR Public
    "lastRecordedPullTime",       # no pull telemetry in ECR Public
    "subjectManifestDigest",
    "imageStatus",
    "lastArchivedAt",
    "lastActivatedAt",
}
_PRIVATE_ONLY_REPOSITORY = {
    "imageTagMutability",              # no tag immutability in ECR Public
    "imageTagMutabilityExclusionFilters",
    "imageScanningConfiguration",      # no scan-on-push in ECR Public
    "encryptionConfiguration",         # no KMS/AES option in ECR Public
}

CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"
MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"

# The pushed bytes are synthetic and meaningless: an ECR Public repository is world-visible on
# gallery.ecr.aws for as long as it exists.


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    kwargs.setdefault(
        "tags", [{"Key": "sim2real-managed", "Value": "true"}, {"Key": "sim2real-check", "Value": CHECK}]
    )
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return name, resp


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


def _push_test_image(ecr, repository_name, tag, seed: bytes = b""):
    """Full data-plane push of synthetic bytes. Returns (manifest_digest, layer_size)."""
    config_bytes = json.dumps({"architecture": "amd64", "os": "linux", "seed": seed.hex()}).encode()
    layer_bytes = b"synthetic-shape-closure-layer-" + seed + bytes(range(32))
    config_digest = _upload_blob(ecr, repository_name, config_bytes)
    layer_digest = _upload_blob(ecr, repository_name, layer_bytes)
    manifest_str = _build_manifest(
        config_digest, len(config_bytes), layer_digest, len(layer_bytes)
    )
    ecr.put_image(
        repositoryName=repository_name,
        imageManifest=manifest_str,
        imageManifestMediaType=MANIFEST_MEDIA_TYPE,
        imageTag=tag,
    )
    return _sha256_digest(manifest_str.encode()), len(config_bytes) + len(layer_bytes)


def _assert_closed(actual, allowed, private_only, *, what):
    """`actual`'s key set is within `allowed`, and names no private-ECR-only member."""
    keys = set(actual) - {"ResponseMetadata"}
    invented = keys & private_only
    assert not invented, (
        f"{what} carries private-ECR-only member(s) {sorted(invented)} that ECR Public does not "
        f"model. ECR Public has no image scanning, no tag immutability, no encryption "
        f"configuration and no pull telemetry, so an emulator answering these is advertising "
        f"features the real service refuses. Got {sorted(keys)}"
    )
    extra = keys - allowed
    assert not extra, (
        f"{what} carries unmodeled member(s) {sorted(extra)}; the model allows exactly "
        f"{sorted(allowed)}"
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Repository and image detail responses carry no member outside the ecr-public model, notably
    none of the private-ECR-only members, since a caller reading them would break on real AWS.

    Reference: https://docs.aws.amazon.com/AmazonECRPublic/latest/APIReference/API_ImageDetail.html
    """
    ecr = ctx.client("ecr-public")

    name, created = _create_repository(ctx, ecr)
    # Key-set closure is sound because the ecr-public model is small and stable.
    _assert_closed(
        created["repository"], _REPOSITORY, _PRIVATE_ONLY_REPOSITORY,
        what="CreateRepository.repository",
    )
    # CreateRepositoryResponse models exactly {repository, catalogData}.
    assert set(created) - {"ResponseMetadata"} <= {"repository", "catalogData"}, sorted(created)

    described = ecr.describe_repositories(repositoryNames=[name])["repositories"]
    assert len(described) == 1, described
    _assert_closed(
        described[0], _REPOSITORY, _PRIVATE_ONLY_REPOSITORY,
        what="DescribeRepositories.repositories[0]",
    )

    tag = "shape-closure"
    manifest_digest, total_blob_bytes = _push_test_image(ecr, name, tag, seed=b"\x01\x02")

    details = ecr.describe_images(repositoryName=name)["imageDetails"]
    matching = [d for d in details if d["imageDigest"] == manifest_digest]
    assert len(matching) == 1, (
        f"expected the pushed image {manifest_digest}, got {[d['imageDigest'] for d in details]}"
    )
    detail = matching[0]
    _assert_closed(
        detail, _IMAGE_DETAIL, _PRIVATE_ONLY_IMAGE_DETAIL, what="DescribeImages.imageDetails[0]"
    )
    # Positive anchors, so the check cannot be satisfied by an empty object.
    assert detail["repositoryName"] == name, detail
    assert tag in detail.get("imageTags", []), detail
    assert isinstance(detail["imageSizeInBytes"], int) and detail["imageSizeInBytes"] > 0, detail
    assert detail["imageSizeInBytes"] <= total_blob_bytes, (
        "imageSizeInBytes is the compressed layer size and cannot exceed the bytes uploaded: "
        f"{detail['imageSizeInBytes']} > {total_blob_bytes}"
    )
    assert detail["imageManifestMediaType"] == MANIFEST_MEDIA_TYPE, detail

    tag_details = ecr.describe_image_tags(repositoryName=name)["imageTagDetails"]
    matching_tags = [t for t in tag_details if t["imageTag"] == tag]
    assert len(matching_tags) == 1, f"expected tag {tag!r}, got {[t.get('imageTag') for t in tag_details]}"
    tag_detail = matching_tags[0]
    _assert_closed(
        tag_detail, _IMAGE_TAG_DETAIL, _PRIVATE_ONLY_IMAGE_DETAIL,
        what="DescribeImageTags.imageTagDetails[0]",
    )
    # ImageTagDetail.imageDetail is a ReferencedImageDetail: FIVE members, and notably NO
    # `imageTags` and NO `repositoryName`. Reusing ImageDetail here would be a superset.
    referenced = tag_detail["imageDetail"]
    _assert_closed(
        referenced, _REFERENCED_IMAGE_DETAIL, _PRIVATE_ONLY_IMAGE_DETAIL,
        what="ImageTagDetail.imageDetail (ReferencedImageDetail)",
    )
    assert "imageTags" not in referenced, (
        "ReferencedImageDetail models no imageTags member; the tag is the sibling field: "
        f"{sorted(referenced)}"
    )
    assert "repositoryName" not in referenced, (
        f"ReferencedImageDetail models no repositoryName member: {sorted(referenced)}"
    )
    assert referenced["imageDigest"] == manifest_digest, (referenced, manifest_digest)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
