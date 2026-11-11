"""put-image-dangling-references-rejected."""
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


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ecr, ctx, name=None, **kwargs):
    """Create a repository with a verified force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    kwargs.setdefault("tags", [{"Key": "sim2real", "Value": CHECK}])
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, name))
    return resp["repository"]


def _delete_repo_verified(ecr, name, timeout_s=60):
    ecr.delete_repository(repositoryName=name, force=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _error_code(lambda: ecr.describe_repositories(repositoryNames=[name]))[0] == "RepositoryNotFoundException":
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


CHECK = "put-image-dangling-references-rejected"
GROUP = 'error-semantics'
SERVICES = ['ecr']


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutImage rejects a manifest naming a never-uploaded layer (LayersNotFoundException) and a
    manifest list naming a missing child (ReferencedImagesNotFoundException), leaving no tag or
    digest behind; the corrected index is accepted."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    repo = _create_repo(ecr, ctx)
    name = repo["repositoryName"]

    layer = b"sim2real-dangling-ref-layer"
    layer_digest, layer_size = _upload_layer(ecr, name, layer)
    config = json.dumps({"architecture": "amd64", "os": "linux", "config": {}}).encode()
    config_digest, config_size = _upload_layer(ecr, name, config)
    child_manifest = _build_manifest(layer_digest, layer_size, config_digest, config_size)
    child_digest = ecr.put_image(
        repositoryName=name,
        imageManifest=child_manifest,
        imageManifestMediaType=DOCKER_MANIFEST_V2,
    )["image"]["imageId"]["imageDigest"]
    baseline = {i["imageDigest"] for i in ecr.list_images(repositoryName=name)["imageIds"]}
    assert baseline == {child_digest}, f"setup left {sorted(baseline)}, expected only the child"

    # The layer digest names a blob that was never uploaded.
    absent_layer = _sha256_digest(b"sim2real-never-uploaded-layer-blob")
    bad_layer_manifest = _build_manifest(absent_layer, 4096, config_digest, config_size)
    code, message = _error_code(
        lambda: ecr.put_image(
            repositoryName=name,
            imageManifest=bad_layer_manifest,
            imageManifestMediaType=DOCKER_MANIFEST_V2,
            imageTag="dangling-layer",
        )
    )
    assert code == "LayersNotFoundException", (
        f"expected LayersNotFoundException for a manifest referencing the un-uploaded blob "
        f"{absent_layer}, got {code}"
    )
    expected_message = (
        f"Layers with digests '[{absent_layer}]' required for pushing image into repository "
        f"with name '{name}' in the registry with id '{account_id}' do not exist"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    after_1 = {i["imageDigest"] for i in ecr.list_images(repositoryName=name)["imageIds"]}
    assert after_1 == baseline, (
        f"the rejected push left state behind: ListImages is now {sorted(after_1)}"
    )
    tag_code, tag_message = _error_code(
        lambda: ecr.describe_images(
            repositoryName=name, imageIds=[{"imageTag": "dangling-layer"}]
        )
    )
    assert tag_code == "ImageNotFoundException", (
        f"tag 'dangling-layer' resolves after a rejected push (DescribeImages returned "
        f"{tag_code!r}); a rejected PutImage must not create a tag"
    )
    expected_tag_message = (
        f"The image with imageId {{imageDigest:'null', imageTag:'dangling-layer'}} does not "
        f"exist within the repository with name '{name}' in the registry with id '{account_id}'"
    )
    assert tag_message == expected_tag_message, f"expected message {expected_tag_message!r}, got {tag_message!r}"

    # The index names a child manifest that does not exist.
    absent_child = _sha256_digest(b"sim2real-never-pushed-child-manifest")
    bad_index = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": DOCKER_MANIFEST_LIST,
            "manifests": [
                {
                    "mediaType": DOCKER_MANIFEST_V2,
                    "size": len(child_manifest.encode()),
                    "digest": child_digest,
                    "platform": {"architecture": "amd64", "os": "linux"},
                },
                {
                    "mediaType": DOCKER_MANIFEST_V2,
                    "size": 1024,
                    "digest": absent_child,
                    "platform": {"architecture": "arm64", "os": "linux"},
                },
            ],
        }
    )
    index_code, index_message = _error_code(
        lambda: ecr.put_image(
            repositoryName=name,
            imageManifest=bad_index,
            imageManifestMediaType=DOCKER_MANIFEST_LIST,
            imageTag="dangling-index",
        )
    )
    assert index_code == "ReferencedImagesNotFoundException", (
        f"expected ReferencedImagesNotFoundException for an index referencing the "
        f"non-existent child {absent_child}, got {index_code}"
    )
    expected_index_message = (
        f"Images with digests '[{absent_child}]' required for pushing image into repository "
        f"with name '{name}' in the registry with id '{account_id}' do not exist"
    )
    assert index_message == expected_index_message, f"expected message {expected_index_message!r}, got {index_message!r}"
    after_2 = {i["imageDigest"] for i in ecr.list_images(repositoryName=name)["imageIds"]}
    assert after_2 == baseline, (
        f"the rejected manifest list left state behind: ListImages is now {sorted(after_2)}"
    )

    # An index over the child that does exist is accepted and tagged.
    good_index = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": DOCKER_MANIFEST_LIST,
            "manifests": [
                {
                    "mediaType": DOCKER_MANIFEST_V2,
                    "size": len(child_manifest.encode()),
                    "digest": child_digest,
                    "platform": {"architecture": "amd64", "os": "linux"},
                }
            ],
        }
    )
    ok = ecr.put_image(
        repositoryName=name,
        imageManifest=good_index,
        imageManifestMediaType=DOCKER_MANIFEST_LIST,
        imageTag="dangling-index",
    )["image"]
    assert ok["imageId"]["imageTag"] == "dangling-index", f"control push echoed {ok['imageId']}"
    assert ok["imageId"]["imageDigest"] == _sha256_digest(good_index.encode()), (
        f"control index stored as {ok['imageId']['imageDigest']}, expected "
        f"{_sha256_digest(good_index.encode())}"
    )
    final = {i["imageDigest"] for i in ecr.list_images(repositoryName=name)["imageIds"]}
    assert final == baseline | {ok["imageId"]["imageDigest"]}, (
        f"after the control push ListImages is {sorted(final)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
