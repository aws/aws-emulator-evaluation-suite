"""describe-images-pagination-and-imageids-projection."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

TAG_NAMES = ("sim2real-a", "sim2real-b", "sim2real-c")


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repo_name, data):
    """InitiateLayerUpload/UploadLayerPart/CompleteLayerUpload in one part; returns (digest, size)."""
    digest = _sha256_digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name, uploadId=upload_id,
        partFirstByte=0, partLastByte=len(data) - 1, layerPartBlob=data,
    )
    ecr.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest, len(data)


def _manifest(config_digest, config_size, layer_digest, layer_size) -> str:
    return json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": config_size, "digest": config_digest,
            },
            "layers": [{
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": layer_size, "digest": layer_digest,
            }],
        },
        sort_keys=True,
    )


def _delete_repo_verified(ecr, name, timeout_s=60):
    """force=True: a repository holding images refuses a plain delete. Confirms it is gone."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "RepositoryNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ecr.describe_repositories(repositoryNames=[name])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "RepositoryNotFoundException":
                return
            raise
        time.sleep(1.0)
    raise AssertionError(f"repository {name!r} still present {timeout_s}s after force delete")


CHECK = "describe-images-pagination-and-imageids-projection"
GROUP = "image-metadata"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeImages paginated with maxResults=1 unions, with no duplicate or dropped digest, to
    exactly the images pushed, and an explicit imageIds list projects to exactly those images.
    """
    ecr = ctx.client("ecr")
    repo = ctx.unique_name("sim2real-behav-ecr-repo-")
    ecr.create_repository(repositoryName=repo, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, repo))

    # One shared layer, three distinct configs, so each tag resolves to a distinct manifest digest.
    layer_digest, layer_size = _upload_blob(ecr, repo, b"sim2real-describe-images-shared-layer\n")
    digest_by_tag = {}
    for tag in TAG_NAMES:
        config = json.dumps(
            {"architecture": "amd64", "os": "linux", "config": {}, "history": [{"created_by": tag}]},
            sort_keys=True,
        ).encode()
        config_digest, config_size = _upload_blob(ecr, repo, config)
        manifest = _manifest(config_digest, config_size, layer_digest, layer_size)
        put = ecr.put_image(repositoryName=repo, imageManifest=manifest, imageTag=tag)
        digest_by_tag[tag] = put["image"]["imageId"]["imageDigest"]
    assert len(set(digest_by_tag.values())) == len(TAG_NAMES), (
        f"the three pushed images resolved to only {len(set(digest_by_tag.values()))} distinct "
        f"digests, expected {len(TAG_NAMES)}: {digest_by_tag!r}"
    )
    all_digests = set(digest_by_tag.values())

    # --- Leg 1: paginated DescribeImages, forced to one item per page, unions to exactly the three.
    seen_digests = []
    for page in ecr.get_paginator("describe_images").paginate(
        repositoryName=repo, PaginationConfig={"PageSize": 1}
    ):
        details = page["imageDetails"]
        assert len(details) <= 1, (
            f"a DescribeImages page requested at PageSize=1 held {len(details)} images: {details!r}"
        )
        seen_digests.extend(d["imageDigest"] for d in details)
    assert len(seen_digests) == len(set(seen_digests)), (
        f"paginating DescribeImages at PageSize=1 repeated a digest: {seen_digests!r}"
    )
    assert set(seen_digests) == all_digests, (
        f"paginating DescribeImages at PageSize=1 saw {sorted(seen_digests)}, expected exactly "
        f"the three pushed digests {sorted(all_digests)}"
    )

    # --- Leg 2: an explicit imageIds list projects the response to exactly those images, not every
    # image in the repository.
    requested_tags = (TAG_NAMES[0], TAG_NAMES[2])
    projected = ecr.describe_images(
        repositoryName=repo,
        imageIds=[{"imageTag": t} for t in requested_tags],
    )["imageDetails"]
    projected_digests = {d["imageDigest"] for d in projected}
    expected_digests = {digest_by_tag[t] for t in requested_tags}
    assert projected_digests == expected_digests, (
        f"DescribeImages with imageIds={list(requested_tags)!r} returned digests "
        f"{sorted(projected_digests)}, expected exactly {sorted(expected_digests)}"
    )
    assert digest_by_tag[TAG_NAMES[1]] not in projected_digests, (
        f"DescribeImages with an explicit imageIds list also returned the unrequested tag "
        f"{TAG_NAMES[1]!r}'s digest, so the list is not a projection"
    )
    for detail in projected:
        assert set(detail.get("imageTags", [])) & set(requested_tags), (
            f"a projected image detail {detail!r} carries none of the requested tags "
            f"{requested_tags!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
