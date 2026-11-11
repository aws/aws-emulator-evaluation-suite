"""list-image-referrers-repository-not-found-rejected."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-image-referrers-repository-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListImageReferrers against a repository that does not exist raises
    RepositoryNotFoundException, and succeeds against a real repository/image."""
    ecr = ctx.client("ecr")
    missing_repo = ctx.unique_name("sim2real-ecr-missing-")
    bogus_digest = "sha256:" + "0" * 64

    code, message = _error(
        lambda: ecr.list_image_referrers(
            repositoryName=missing_repo, subjectId={"imageDigest": bogus_digest}
        )
    )
    assert code == "RepositoryNotFoundException", code
    assert message == (
        f"The repository with name '{missing_repo}' does not exist in the registry with id '{ctx.account}'"
    ), message

    # Effect-absent: the repository really does not exist.
    describe_code, describe_message = _error(
        lambda: ecr.describe_repositories(repositoryNames=[missing_repo])
    )
    assert describe_code == "RepositoryNotFoundException", describe_code
    assert describe_message == (
        f"The repository with name '{missing_repo}' does not exist in the registry with id '{ctx.account}'"
    ), describe_message

    # Positive control: a real repository + image resolves without error.
    repo = _create_repo(ctx, ecr)
    image = _push_minimal_image(ecr, repo, "present")
    resp = ecr.list_image_referrers(
        repositoryName=repo, subjectId={"imageDigest": image["digest"]}
    )
    assert resp["referrers"] == [], resp["referrers"]


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ctx, ecr) -> str:
    name = ctx.unique_name("sim2real-ecr-behav-")
    ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _delete_repo_force(ecr, name))
    return name


def _delete_repo_force(ecr, name: str) -> None:
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repo_name: str, data: bytes) -> str:
    digest = _sha256_digest(data)
    upload = ecr.initiate_layer_upload(repositoryName=repo_name)
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload["uploadId"],
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload["uploadId"], layerDigests=[digest]
    )
    return digest


def _push_minimal_image(ecr, repo_name: str, tag: str) -> dict:
    config_bytes = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": []},
        }
    ).encode()
    layer_bytes = f"sim2real-ecr-behavioral-layer-blob-{tag}".encode()
    config_digest = _upload_blob(ecr, repo_name, config_bytes)
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)
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
    manifest_bytes = json.dumps(manifest).encode()
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=manifest_bytes.decode(), imageTag=tag
    )
    image = resp["image"]
    return {
        "digest": image["imageId"]["imageDigest"],
        "tag": tag,
        "manifest_bytes": manifest_bytes,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
