"""immutable-tag-exclusion-filter-scoped."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

DOCKER_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG_V1 = "application/vnd.docker.container.image.v1+json"
DOCKER_LAYER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ecr, ctx, name=None, **kwargs):
    """Create a repository with a verified force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, name))
    return resp["repository"]


def _delete_repo_verified(ecr, name, timeout_s=60):
    ecr.delete_repository(repositoryName=name, force=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ecr.describe_repositories(repositoryNames=[name])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "RepositoryNotFoundException":
                return
            raise
        time.sleep(1.0)
    raise AssertionError(f"repository {name} still present {timeout_s}s after force delete")


def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_layer(ecr, repo_name, data):
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
    return json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": DOCKER_MANIFEST_V2,
            "config": {
                "mediaType": DOCKER_CONFIG_V1,
                "size": config_size,
                "digest": config_digest,
            },
            "layers": [
                {"mediaType": DOCKER_LAYER_GZIP, "size": layer_size, "digest": layer_digest}
            ],
        }
    )


def _manifest_for(ecr, repo_name, seed):
    """Upload a distinct layer+config pair and return the manifest (not yet pushed)."""
    layer_digest, layer_size = _upload_layer(ecr, repo_name, b"layer-" + seed)
    config = b'{"architecture":"amd64","os":"linux","config":{},"seed":"' + seed + b'"}'
    config_digest, config_size = _upload_layer(ecr, repo_name, config)
    return _build_manifest(layer_digest, layer_size, config_digest, config_size)


CHECK = "immutable-tag-exclusion-filter-scoped"
GROUP = 'image-tag-mutability'
SERVICES = ['ecr']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """IMMUTABLE_WITH_EXCLUSION freezes every tag except those matching the exclusion filters: a
    `dev*` tag can move to a new digest, a release tag is refused and keeps its digest until the
    repository is relaxed to MUTABLE."""
    ecr = ctx.client("ecr")
    repo = _create_repo(
        ecr,
        ctx,
        imageTagMutability="IMMUTABLE_WITH_EXCLUSION",
        imageTagMutabilityExclusionFilters=[{"filterType": "WILDCARD", "filter": "dev*"}],
    )
    name = repo["repositoryName"]
    assert repo["imageTagMutability"] == "IMMUTABLE_WITH_EXCLUSION", (
        f"CreateRepository echoed imageTagMutability {repo.get('imageTagMutability')!r}"
    )
    assert repo["imageTagMutabilityExclusionFilters"] == [
        {"filterType": "WILDCARD", "filter": "dev*"}
    ], (
        f"CreateRepository echoed exclusion filters {repo.get('imageTagMutabilityExclusionFilters')!r}"
    )

    described = ecr.describe_repositories(repositoryNames=[name])["repositories"][0]
    assert described["imageTagMutability"] == "IMMUTABLE_WITH_EXCLUSION", (
        f"DescribeRepositories reports {described.get('imageTagMutability')!r}; the setting did "
        f"not persist"
    )
    assert described["imageTagMutabilityExclusionFilters"] == [
        {"filterType": "WILDCARD", "filter": "dev*"}
    ], (
        f"DescribeRepositories reports filters {described.get('imageTagMutabilityExclusionFilters')!r}; "
        f"an emulator that stores the enum but drops the filter list fails here"
    )

    manifest_a = _manifest_for(ecr, name, b"first")
    manifest_b = _manifest_for(ecr, name, b"second")
    digest_a = _sha256_digest(manifest_a.encode())
    digest_b = _sha256_digest(manifest_b.encode())
    assert digest_a != digest_b, (
        f"the two seeded manifests hashed to the same digest {digest_a!r}; the test needs two "
        f"distinct digests to prove a tag moved"
    )

    for tag in ("dev-1", "rel-1"):
        pushed = ecr.put_image(
            repositoryName=name,
            imageManifest=manifest_a,
            imageManifestMediaType=DOCKER_MANIFEST_V2,
            imageTag=tag,
        )["image"]
        assert pushed["imageId"]["imageDigest"] == digest_a, (
            f"initial push of {tag} landed on {pushed['imageId']['imageDigest']}, expected {digest_a}"
        )

    # Excluded pattern: dev-1 matches "dev*", so moving it to a different digest is allowed.
    moved = ecr.put_image(
        repositoryName=name,
        imageManifest=manifest_b,
        imageManifestMediaType=DOCKER_MANIFEST_V2,
        imageTag="dev-1",
    )["image"]
    assert moved["imageId"]["imageDigest"] == digest_b, (
        f"re-tagging the excluded tag dev-1 landed on {moved['imageId']['imageDigest']}, "
        f"expected {digest_b}"
    )

    # rel-1 does not match the exclusion filter, so repointing it is refused.
    code, message = _error(
        lambda: ecr.put_image(
            repositoryName=name,
            imageManifest=manifest_b,
            imageManifestMediaType=DOCKER_MANIFEST_V2,
            imageTag="rel-1",
        )
    )
    assert code == "ImageTagAlreadyExistsException", (
        f"expected ImageTagAlreadyExistsException when repointing rel-1, which does not match "
        f"the exclusion filter 'dev*', got {code}"
    )
    assert message == (
        f"The image tag 'rel-1' already exists in the '{name}' repository and cannot be overwritten because the tag is immutable."
    ), message

    # dev-1 moved, rel-1 did not.
    details = ecr.describe_images(repositoryName=name)["imageDetails"]
    tags_by_digest = {d["imageDigest"]: set(d.get("imageTags", [])) for d in details}
    assert "dev-1" in tags_by_digest.get(digest_b, set()), (
        f"dev-1 is not on {digest_b}; tags are {tags_by_digest}"
    )
    assert "dev-1" not in tags_by_digest.get(digest_a, set()), (
        f"dev-1 is still on the old digest {digest_a}; a moved tag must not be duplicated"
    )
    assert "rel-1" in tags_by_digest.get(digest_a, set()), (
        f"rel-1 no longer resolves to its original digest {digest_a}; tags are {tags_by_digest}"
    )
    assert "rel-1" not in tags_by_digest.get(digest_b, set()), (
        f"rel-1 was repointed to {digest_b} despite the rejection"
    )

    # Relaxing the repository to MUTABLE lets the refused call through, so the refusal came from
    # the mutability setting.
    updated = ecr.put_image_tag_mutability(
        repositoryName=name, imageTagMutability="MUTABLE"
    )
    assert updated["imageTagMutability"] == "MUTABLE", (
        f"PutImageTagMutability echoed {updated.get('imageTagMutability')!r}"
    )
    now = ecr.put_image(
        repositoryName=name,
        imageManifest=manifest_b,
        imageManifestMediaType=DOCKER_MANIFEST_V2,
        imageTag="rel-1",
    )["image"]
    assert now["imageId"]["imageDigest"] == digest_b, (
        f"after relaxing to MUTABLE, rel-1 landed on {now['imageId']['imageDigest']}, "
        f"expected {digest_b}"
    )
    # DescribeImages' tag index is eventually consistent after a repoint and can report the
    # pre-move tag set for a few seconds, so poll within a bounded window.
    def _tags_by_digest():
        return {
            d["imageDigest"]: set(d.get("imageTags", []))
            for d in ecr.describe_images(repositoryName=name)["imageDetails"]
        }

    deadline = time.monotonic() + 60.0
    final = _tags_by_digest()
    while final.get(digest_b, set()) != {"dev-1", "rel-1"} and time.monotonic() < deadline:
        time.sleep(2.0)
        final = _tags_by_digest()
    assert final.get(digest_b, set()) == {"dev-1", "rel-1"}, (
        f"expected both tags on {digest_b}, got {final}"
    )
    assert final.get(digest_a, set()) == set(), (
        f"digest_a {digest_a} must be left untagged once both tags point at {digest_b}, "
        f"got {final}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
