"""batch-delete-image-untags-shared-digest."""
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
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
        try:
            ecr.describe_repositories(repositoryNames=[name])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "RepositoryNotFoundException":
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
    layer_digest, layer_size = _upload_layer(ecr, repo_name, b"layer-" + seed)
    config = b'{"architecture":"amd64","os":"linux","config":{},"seed":"' + seed + b'"}'
    config_digest, config_size = _upload_layer(ecr, repo_name, config)
    return _build_manifest(layer_digest, layer_size, config_digest, config_size)


def _tags_by_digest(ecr, repo_name):
    return {
        d["imageDigest"]: set(d.get("imageTags", []))
        for d in ecr.describe_images(repositoryName=repo_name)["imageDetails"]
    }


CHECK = "batch-delete-image-untags-shared-digest"
GROUP = 'image-data-plane'
SERVICES = ['ecr']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Deleting one of several tags on a digest untags it; deleting the last tag or the digest
    removes the image and every tag, leaving unrelated images untouched."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ecr, ctx, tags=[{"Key": "sim2real", "Value": CHECK}])
    name = repo["repositoryName"]

    shared = _manifest_for(ecr, name, b"shared")
    other = _manifest_for(ecr, name, b"other")
    shared_digest = _sha256_digest(shared.encode())
    other_digest = _sha256_digest(other.encode())
    assert shared_digest != other_digest

    for tag in ("v1", "v1-alias", "latest"):
        pushed = ecr.put_image(
            repositoryName=name,
            imageManifest=shared,
            imageManifestMediaType=DOCKER_MANIFEST_V2,
            imageTag=tag,
        )["image"]
        assert pushed["imageId"]["imageDigest"] == shared_digest, (
            f"pushing tag {tag} produced digest {pushed['imageId']['imageDigest']}, expected "
            f"{shared_digest}; the same manifest bytes must always resolve to the same digest"
        )
    ecr.put_image(
        repositoryName=name,
        imageManifest=other,
        imageManifestMediaType=DOCKER_MANIFEST_V2,
        imageTag="unrelated",
    )

    start = _tags_by_digest(ecr, name)
    assert start[shared_digest] == {"v1", "v1-alias", "latest"}, (
        f"setup: {shared_digest} carries {start.get(shared_digest)}, expected 3 tags"
    )
    assert start[other_digest] == {"unrelated"}, (
        f"setup: {other_digest} carries {start.get(other_digest)}"
    )
    # Two digests, four tag references: ListImages reports one entry per tag.
    listed = ecr.list_images(repositoryName=name)["imageIds"]
    assert sorted(i.get("imageTag") for i in listed) == [
        "latest",
        "unrelated",
        "v1",
        "v1-alias",
    ], f"ListImages reported {listed}"

    # Delete one of three tags: an untag, not a delete.
    first = ecr.batch_delete_image(repositoryName=name, imageIds=[{"imageTag": "v1"}])
    assert first.get("failures", []) == [], f"deleting tag v1 failed: {first.get('failures')}"
    assert [i.get("imageTag") for i in first["imageIds"]] == ["v1"], (
        f"BatchDeleteImage reported {first.get('imageIds')} for a single-tag delete"
    )
    after_first = _tags_by_digest(ecr, name)
    assert shared_digest in after_first, (
        f"{shared_digest} was destroyed by deleting one of its three tags; only the tag "
        f"reference should have been removed. DescribeImages now: {after_first}"
    )
    assert after_first[shared_digest] == {"v1-alias", "latest"}, (
        f"expected the two surviving tags on {shared_digest}, got {after_first[shared_digest]}"
    )
    # The image is still fully pullable through a surviving tag.
    got = ecr.batch_get_image(
        repositoryName=name,
        imageIds=[{"imageTag": "latest"}],
        acceptedMediaTypes=[DOCKER_MANIFEST_V2],
    )
    assert got.get("failures", []) == [], f"the surviving tag is not resolvable: {got}"
    assert got["images"][0]["imageManifest"] == shared, (
        "the manifest reachable through the surviving tag is not the one that was pushed"
    )
    assert got["images"][0]["imageId"]["imageDigest"] == shared_digest

    # The deleted tag itself is gone.
    code, message = _error(
        lambda: ecr.describe_images(repositoryName=name, imageIds=[{"imageTag": "v1"}])
    )
    assert code == "ImageNotFoundException", f"the deleted tag v1 still resolves: {code!r}"
    expected = (
        f"The image with imageId {{imageDigest:'null', imageTag:'v1'}} does not exist within "
        f"the repository with name '{name}' in the registry with id '{ctx.account}'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Deleting by digest removes every remaining tag of that digest in one call, and does not
    # touch the unrelated image.
    by_digest = ecr.batch_delete_image(
        repositoryName=name, imageIds=[{"imageDigest": shared_digest}]
    )
    assert by_digest.get("failures", []) == [], f"digest delete failed: {by_digest.get('failures')}"
    returned_tags = {i.get("imageTag") for i in by_digest["imageIds"]}
    assert returned_tags == {"v1-alias", "latest"}, (
        f"deleting by digest reported {by_digest['imageIds']}; both remaining tag references "
        f"must be reported as removed"
    )
    assert {i["imageDigest"] for i in by_digest["imageIds"]} == {shared_digest}
    end = _tags_by_digest(ecr, name)
    assert shared_digest not in end, (
        f"{shared_digest} survived a delete-by-digest that removed its last tags: {end}"
    )
    assert end == {other_digest: {"unrelated"}}, (
        f"the unrelated image was collaterally affected; DescribeImages: {end}"
    )
    # A deleted digest must come back as a per-item failure inside a 200, not as an exception.
    gone = ecr.batch_get_image(
        repositoryName=name,
        imageIds=[{"imageDigest": shared_digest}],
        acceptedMediaTypes=[DOCKER_MANIFEST_V2],
    )
    assert gone.get("images", []) == [], f"the deleted digest is still fetchable: {gone}"
    assert len(gone.get("failures", [])) == 1 and gone["failures"][0][
        "failureCode"
    ] == "ImageNotFound", (
        f"expected one ImageNotFound failure for the deleted digest, got {gone.get('failures')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
