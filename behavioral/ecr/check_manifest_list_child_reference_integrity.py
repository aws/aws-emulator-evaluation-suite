"""manifest-list-child-reference-integrity."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

DOCKER_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_MANIFEST_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
DOCKER_CONFIG_V1 = "application/vnd.docker.container.image.v1+json"
DOCKER_LAYER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"


def _repo_absent(ecr, name):
    """True once DescribeRepositories refuses `name` with RepositoryNotFoundException."""
    try:
        ecr.describe_repositories(repositoryNames=[name])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "RepositoryNotFoundException":
            return True
        raise
    return False


def _create_repo(ecr, ctx, name=None, **kwargs):
    """Create a repository with a verified force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, name))
    return resp["repository"]


def _delete_repo_verified(ecr, name, timeout_s=60):
    ecr.delete_repository(repositoryName=name, force=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _repo_absent(ecr, name):
            return
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


def _push_child(ecr, repo_name, arch):
    """Push an untagged single-platform image; return its manifest, which a manifest list must
    reference by size and digest."""
    layer = b"rootfs-for-" + arch.encode()
    layer_digest, layer_size = _upload_layer(ecr, repo_name, layer)
    config = json.dumps({"architecture": arch, "os": "linux", "config": {}}).encode()
    config_digest, config_size = _upload_layer(ecr, repo_name, config)
    manifest_str = json.dumps(
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
    image = ecr.put_image(
        repositoryName=repo_name,
        imageManifest=manifest_str,
        imageManifestMediaType=DOCKER_MANIFEST_V2,
    )["image"]
    return {
        "arch": arch,
        "digest": image["imageId"]["imageDigest"],
        "manifest": manifest_str,
        "config_digest": config_digest,
    }


CHECK = "manifest-list-child-reference-integrity"
GROUP = 'image-data-plane'
SERVICES = ['ecr']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A manifest list is stored under the sha256 of its bytes and resolves each platform to the
    pushed untagged child; deleting a referenced child fails with ImageReferencedByManifestList
    and deletes nothing, and succeeds once the index is gone."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ecr, ctx, tags=[{"Key": "sim2real", "Value": CHECK}])
    name = repo["repositoryName"]

    children = [_push_child(ecr, name, "amd64"), _push_child(ecr, name, "arm64")]
    for child in children:
        assert child["digest"] == _sha256_digest(child["manifest"].encode()), (
            f"PutImage stored the {child['arch']} child under {child['digest']} but sha256 of "
            f"the bytes sent is {_sha256_digest(child['manifest'].encode())}; the registry is "
            f"not content-addressing the manifest it received"
        )
    assert children[0]["digest"] != children[1]["digest"], "the two children collided"

    index_str = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": DOCKER_MANIFEST_LIST,
            "manifests": [
                {
                    "mediaType": DOCKER_MANIFEST_V2,
                    "size": len(child["manifest"].encode()),
                    "digest": child["digest"],
                    "platform": {"architecture": child["arch"], "os": "linux"},
                }
                for child in children
            ],
        }
    )
    index_digest_expected = _sha256_digest(index_str.encode())
    tag = "multi"
    index_image = ecr.put_image(
        repositoryName=name,
        imageManifest=index_str,
        imageManifestMediaType=DOCKER_MANIFEST_LIST,
        imageTag=tag,
    )["image"]
    assert index_image["imageId"]["imageDigest"] == index_digest_expected, (
        f"manifest list stored as {index_image['imageId']['imageDigest']}, expected "
        f"{index_digest_expected}"
    )
    assert index_image["imageManifestMediaType"] == DOCKER_MANIFEST_LIST, (
        f"PutImage reported {index_image.get('imageManifestMediaType')!r} for a manifest list"
    )

    detail = ecr.describe_images(repositoryName=name, imageIds=[{"imageTag": tag}])["imageDetails"][0]
    assert detail["imageManifestMediaType"] == DOCKER_MANIFEST_LIST, (
        f"DescribeImages reports {detail.get('imageManifestMediaType')!r} for the index"
    )

    # The index is the only tagged image; its children stay untagged and separately listed.
    listed = ecr.list_images(repositoryName=name)["imageIds"]
    digests = {i["imageDigest"] for i in listed}
    assert digests == {children[0]["digest"], children[1]["digest"], index_digest_expected}, (
        f"ListImages returned {sorted(digests)}, expected the 2 children plus the index"
    )
    tagged = {i["imageDigest"] for i in listed if i.get("imageTag")}
    assert tagged == {index_digest_expected}, (
        f"tagged digests are {sorted(tagged)}; only the manifest list carries a tag"
    )

    # Platform resolution: each index entry must fetch back the exact child manifest, and its
    # config digest must be the one belonging to that architecture.
    fetched_index = ecr.batch_get_image(
        repositoryName=name,
        imageIds=[{"imageTag": tag}],
        acceptedMediaTypes=[DOCKER_MANIFEST_LIST],
    )
    assert fetched_index.get("failures", []) == [], f"failures: {fetched_index.get('failures')}"
    assert fetched_index["images"][0]["imageManifest"] == index_str, (
        "BatchGetImage did not return the manifest list byte-for-byte"
    )
    entries = json.loads(fetched_index["images"][0]["imageManifest"])["manifests"]
    by_arch = {child["arch"]: child for child in children}
    assert {e["platform"]["architecture"] for e in entries} == set(by_arch), (
        f"index platforms {[e['platform'] for e in entries]} do not match the pushed children"
    )
    for entry in entries:
        arch = entry["platform"]["architecture"]
        expected = by_arch[arch]
        assert entry["digest"] == expected["digest"], (
            f"index entry for {arch} points at {entry['digest']}, expected {expected['digest']}"
        )
        got = ecr.batch_get_image(
            repositoryName=name,
            imageIds=[{"imageDigest": entry["digest"]}],
            acceptedMediaTypes=[DOCKER_MANIFEST_V2],
        )
        assert len(got["images"]) == 1, f"child {arch} not resolvable by digest: {got}"
        child_manifest = got["images"][0]["imageManifest"]
        assert child_manifest == expected["manifest"], (
            f"child manifest for {arch} came back modified: {child_manifest!r}"
        )
        assert json.loads(child_manifest)["config"]["digest"] == expected["config_digest"], (
            f"the {arch} entry resolved to a manifest whose config is not the {arch} config"
        )
        assert entry["size"] == len(expected["manifest"].encode()), (
            f"index entry size {entry['size']} != child manifest byte length "
            f"{len(expected['manifest'].encode())}"
        )

    # Reference integrity: a child of a live index must not be deletable.
    victim = children[0]["digest"]
    deleted = ecr.batch_delete_image(
        repositoryName=name, imageIds=[{"imageDigest": victim}]
    )
    assert deleted.get("imageIds", []) == [], (
        f"BatchDeleteImage deleted a child referenced by a manifest list: {deleted.get('imageIds')}"
    )
    failures = deleted.get("failures", [])
    assert len(failures) == 1, f"expected exactly 1 failure, got {failures}"
    assert failures[0]["failureCode"] == "ImageReferencedByManifestList", (
        f"failureCode is {failures[0].get('failureCode')!r}, expected "
        f"'ImageReferencedByManifestList' (a modeled ImageFailureCode)"
    )
    expected_reason = f"Requested image referenced by manifest list: [{index_digest_expected}]"
    assert failures[0].get("failureReason") == expected_reason, (
        f"failureReason is {failures[0].get('failureReason')!r}, expected {expected_reason!r}"
    )
    assert failures[0]["imageId"]["imageDigest"] == victim, (
        f"failure names {failures[0].get('imageId')}, expected the digest we asked to delete"
    )
    still = {i["imageDigest"] for i in ecr.list_images(repositoryName=name)["imageIds"]}
    assert victim in still, f"{victim} disappeared despite the reported failure"
    assert still == digests, f"ListImages changed to {sorted(still)} after a failed delete"

    # Control: remove the index, then the identical delete succeeds.
    dropped = ecr.batch_delete_image(
        repositoryName=name, imageIds=[{"imageDigest": index_digest_expected}]
    )
    assert dropped.get("failures", []) == [], f"deleting the index failed: {dropped}"
    assert [i["imageDigest"] for i in dropped["imageIds"]] == [index_digest_expected], (
        f"BatchDeleteImage reported {dropped.get('imageIds')} for the index delete"
    )
    now = ecr.batch_delete_image(repositoryName=name, imageIds=[{"imageDigest": victim}])
    assert now.get("failures", []) == [], (
        f"child delete still failed after the index was removed: {now.get('failures')}"
    )
    assert [i["imageDigest"] for i in now["imageIds"]] == [victim], (
        f"BatchDeleteImage reported {now.get('imageIds')}, expected {victim}"
    )
    final = {i["imageDigest"] for i in ecr.list_images(repositoryName=name)["imageIds"]}
    assert final == {children[1]["digest"]}, (
        f"expected only the surviving child {children[1]['digest']}, got {sorted(final)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
