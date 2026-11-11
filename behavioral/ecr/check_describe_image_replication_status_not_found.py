"""describe-image-replication-status-not-found."""
from __future__ import annotations

import hashlib
import json
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-image-replication-status-not-found"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeImageReplicationStatus is refused RepositoryNotFoundException for a missing
    repository and ImageNotFoundException for a missing tag, each with the exact message, while a
    pushed image returns its digest and a replicationStatuses list."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-replstatus-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    unknown_repo = ctx.unique_name("sim2real-ecr-noexist-")
    code_repo, code_repo_msg = _error(
        lambda: ecr.describe_image_replication_status(
            repositoryName=unknown_repo, imageId={"imageTag": "whatever"}
        )
    )
    assert code_repo == "RepositoryNotFoundException", (
        f"expected RepositoryNotFoundException for nonexistent repo {unknown_repo!r}, got {code_repo!r}"
    )
    expected_msg = f"The repository with name '{unknown_repo}' does not exist in the registry with id '{ctx.account}'"
    assert code_repo_msg == expected_msg, f"expected message {expected_msg!r}, got {code_repo_msg!r}"

    code_image, code_image_msg = _error(
        lambda: ecr.describe_image_replication_status(
            repositoryName=repo_name, imageId={"imageTag": "no-such-tag"}
        )
    )
    assert code_image == "ImageNotFoundException", (
        f"expected ImageNotFoundException for untagged image in real repo {repo_name!r}, got {code_image!r}"
    )
    expected_msg = (
        f"The image with imageId {{imageDigest:'null', imageTag:'no-such-tag'}} does not exist within the "
        f"repository with name '{repo_name}' in the registry with id '{ctx.account}'"
    )
    assert code_image_msg == expected_msg, f"expected message {expected_msg!r}, got {code_image_msg!r}"

    # positive control: a real pushed image describes without raising
    image = _push_minimal_image(ecr, repo_name, "present")
    resp = ecr.describe_image_replication_status(
        repositoryName=repo_name, imageId={"imageTag": "present"}
    )
    assert resp["imageId"]["imageDigest"] == image["imageId"]["imageDigest"], (
        f"expected describe to resolve the pushed digest {image['imageId']['imageDigest']!r}, "
        f"got {resp['imageId']['imageDigest']!r}"
    )
    assert isinstance(resp["replicationStatuses"], list), (
        f"expected replicationStatuses to be a list, got {resp['replicationStatuses']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _upload_blob(ecr, repo_name: str, data: bytes) -> tuple[str, int]:
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


def _push_minimal_image(ecr, repo_name: str, tag: str) -> dict:
    config_digest, config_size = _upload_blob(ecr, repo_name, json.dumps({"sim2real": tag}).encode())
    layer_digest, layer_size = _upload_blob(ecr, repo_name, os.urandom(128))
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": config_size,
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": layer_size,
                "digest": layer_digest,
            }
        ],
    }
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=json.dumps(manifest), imageTag=tag
    )
    return resp["image"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
