"""e2e-image-push-pull-tag-delete-flow."""
from __future__ import annotations

import hashlib
import json
import time

from behavioral_harness import tags

CHECK = "e2e-image-push-pull-tag-delete-flow"
GROUP = "state-machine"
SERVICES = ["ecr-public"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _ecrpub_client(ctx):
    """A ctx client for ecr-public pinned to us-east-1, the only region that serves it."""
    return ctx.client("ecr-public", region="us-east-1")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pushed image's tag is listed by DescribeImageTags; after force DeleteRepository, both
    the repository and its images fail RepositoryNotFoundException.
    """
    ecrpub = _ecrpub_client(ctx)
    repo_name = ctx.unique_name("sim2real-ecrpub-e2e-")

    ecrpub.create_repository(
        repositoryName=repo_name,
        tags=[{"Key": "sim2real-check", "Value": "e2e-image-push-pull-tag-delete-flow"}],
    )
    # Safety net: a failure before the in-band delete must not leak the repository.
    ctx.on_cleanup(lambda: _delete_repo_if_present(ecrpub, repo_name))

    layer_bytes = f"sim2real-ecrpub-e2e-layer-{time.time_ns()}".encode() * 64
    config_bytes = b'{"architecture":"amd64","os":"linux","config":{}}'
    layer_digest = _upload_blob(ecrpub, repo_name, layer_bytes)
    config_digest = _upload_blob(ecrpub, repo_name, config_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": f"sha256:{config_digest}",
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_bytes),
                "digest": f"sha256:{layer_digest}",
            }
        ],
    }
    put_resp = ecrpub.put_image(
        repositoryName=repo_name,
        imageManifest=json.dumps(manifest),
        imageTag="e2e-flow",
    )
    image_digest = put_resp["image"]["imageId"]["imageDigest"]

    tag_details = ecrpub.describe_image_tags(repositoryName=repo_name)["imageTagDetails"]
    tags_seen = {t["imageTag"]: t["imageDetail"]["imageDigest"] for t in tag_details}
    assert tags_seen.get("e2e-flow") == image_digest, (
        f"DescribeImageTags reported {tags_seen!r} for tag 'e2e-flow'; expected it to map to "
        f"the digest PutImage returned, {image_digest!r}"
    )

    # Delete the (non-empty) repository -- requires force=True.
    ecrpub.delete_repository(repositoryName=repo_name, force=True)

    code, code_msg = _error_code(lambda: ecrpub.describe_repositories(repositoryNames=[repo_name]))
    assert code == "RepositoryNotFoundException", (
        f"DescribeRepositories after DeleteRepository answered code={code!r}, expected "
        f"'RepositoryNotFoundException'"
    )
    expected_code_msg = f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
    assert code_msg == expected_code_msg, f"expected message {expected_code_msg!r}, got {code_msg!r}"

    code_images, code_images_msg = _error_code(lambda: ecrpub.describe_images(repositoryName=repo_name))
    assert code_images == "RepositoryNotFoundException", (
        f"DescribeImages against the deleted repository answered code={code_images!r}, "
        f"expected 'RepositoryNotFoundException'"
    )
    expected_code_images_msg = f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
    assert code_images_msg == expected_code_images_msg, f"expected message {expected_code_images_msg!r}, got {code_images_msg!r}"


def _upload_blob(client, repository_name: str, data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    upload = client.initiate_layer_upload(repositoryName=repository_name)
    upload_id = upload["uploadId"]
    client.upload_layer_part(
        repositoryName=repository_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    client.complete_layer_upload(
        repositoryName=repository_name,
        uploadId=upload_id,
        layerDigests=[f"sha256:{digest}"],
    )
    return digest


def _delete_repo_if_present(client, repository_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        client.delete_repository(repositoryName=repository_name, force=True)
    except ClientError as err:
        if err.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
