"""repository-delete-non-empty-rejected."""
from __future__ import annotations

import hashlib
import json
import os

from behavioral_harness import tags

CHECK = "repository-delete-non-empty-rejected"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRepository without force succeeds on an empty repository but is rejected with
    RepositoryNotEmptyException once it holds an image, leaving repository and image intact;
    after BatchDeleteImage removes the image, the same non-force call succeeds."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-nonempty-")
    state = {"deleted": False}

    def _cleanup() -> None:
        if not state["deleted"]:
            _delete_repository_or_ignore(ecr, repo_name)

    ctx.on_cleanup(_cleanup)

    ecr.create_repository(repositoryName=repo_name)

    # Positive control: the rejection below is attributable to the image, not the call.
    ecr.delete_repository(repositoryName=repo_name)
    control_code, control_message = _client_error(
        lambda: ecr.describe_repositories(repositoryNames=[repo_name])
    )
    assert control_code == "RepositoryNotFoundException", (
        f"expected the empty-repository delete to leave the repo not-found, got {control_code!r}"
    )
    assert control_message == (
        f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
    ), control_message

    # Freed repository names are reusable.
    ecr.create_repository(repositoryName=repo_name)
    image_digest = _push_minimal_image(ecr, repo_name, "v1")

    code, message = _client_error(lambda: ecr.delete_repository(repositoryName=repo_name))
    assert code == "RepositoryNotEmptyException", (
        f"expected RepositoryNotEmptyException for a non-empty repository, got {code!r}"
    )
    assert message == (
        f"The repository with name '{repo_name}' in registry with id '{ctx.account}' "
        "cannot be deleted because it still contains images"
    ), message

    repos = ecr.describe_repositories(repositoryNames=[repo_name])["repositories"]
    assert len(repos) == 1, f"expected the rejected delete to leave the repository, got {repos!r}"
    images = ecr.describe_images(repositoryName=repo_name)["imageDetails"]
    assert len(images) == 1, f"expected the rejected delete to leave the image, got {images!r}"

    ecr.batch_delete_image(repositoryName=repo_name, imageIds=[{"imageDigest": image_digest}])
    images_after = ecr.describe_images(repositoryName=repo_name)["imageDetails"]
    assert images_after == [], (
        f"expected BatchDeleteImage to empty the repository, still saw {images_after!r}"
    )

    ecr.delete_repository(repositoryName=repo_name)
    state["deleted"] = True
    code2, message2 = _client_error(lambda: ecr.describe_repositories(repositoryNames=[repo_name]))
    assert code2 == "RepositoryNotFoundException", (
        f"expected the restored delete to leave the repo not-found, got {code2!r}"
    )
    assert message2 == (
        f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
    ), message2




def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repo_name: str, data: bytes) -> str:
    digest = f"sha256:{_sha256_hex(data)}"
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest


def _push_minimal_image(ecr, repo_name: str, tag: str) -> str:
    layer_bytes = b"sim2real-ecr-layer-" + os.urandom(16)
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
        "history": [{"created": "2024-01-01T00:00:00Z", "created_by": "sim2real"}],
    }
    config_bytes = json.dumps(config).encode("utf-8")
    config_digest = _upload_blob(ecr, repo_name, config_bytes)

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_bytes),
                "digest": layer_digest,
            }
        ],
    }
    manifest_bytes = json.dumps(manifest).encode("utf-8")
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=manifest_bytes.decode("utf-8"), imageTag=tag
    )
    return resp["image"]["imageId"]["imageDigest"]


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _delete_repository_or_ignore(ecr, repo_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as err:
        if err.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
