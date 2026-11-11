"""list-image-referrers-repository-not-found."""
from __future__ import annotations

import hashlib
import json
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-image-referrers-repository-not-found"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListImageReferrers against a repository that was just deleted raises
    RepositoryNotFoundException on both a read and a mutation attempt, while the same
    repository name -- once recreated -- is fully usable again."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-referrers-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _best_effort_delete_repo(ecr, repo_name))

    image = _push_minimal_image(ecr, repo_name, "present")
    subject_digest = image["imageId"]["imageDigest"]

    # positive control first, while the repository still exists
    ok_resp = ecr.list_image_referrers(
        repositoryName=repo_name, subjectId={"imageDigest": subject_digest}
    )
    assert isinstance(ok_resp["referrers"], list), (
        f"ListImageReferrers against a live repository with a real image must succeed "
        f"and return a referrers list, got {ok_resp!r}"
    )

    ecr.delete_repository(repositoryName=repo_name, force=True)

    read_code, read_message = _error(
        lambda: ecr.list_image_referrers(
            repositoryName=repo_name, subjectId={"imageDigest": subject_digest}
        )
    )
    assert read_code == "RepositoryNotFoundException", (
        f"ListImageReferrers against a just-deleted repository should raise "
        f"RepositoryNotFoundException, got {read_code!r}"
    )
    assert read_message == (
        f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
    ), read_message

    # the effect is not just absent from this one read -- a mutation against the dead
    # repository must fail the same way, not silently start writing into nothing
    mutation_code, mutation_message = _error(
        lambda: ecr.initiate_layer_upload(repositoryName=repo_name)
    )
    assert mutation_code == "RepositoryNotFoundException", (
        f"InitiateLayerUpload against a just-deleted repository should raise "
        f"RepositoryNotFoundException, got {mutation_code!r}"
    )
    assert mutation_message == (
        f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
    ), mutation_message

    # the name is not wedged: recreating it and pushing again works exactly as before
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    reused_image = _push_minimal_image(ecr, repo_name, "present-again")
    reused_resp = ecr.list_image_referrers(
        repositoryName=repo_name,
        subjectId={"imageDigest": reused_image["imageId"]["imageDigest"]},
    )
    assert isinstance(reused_resp["referrers"], list), (
        f"ListImageReferrers against the recreated repository must succeed just like "
        f"it did before deletion, got {reused_resp!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _best_effort_delete_repo(ecr, repo_name):
    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


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
