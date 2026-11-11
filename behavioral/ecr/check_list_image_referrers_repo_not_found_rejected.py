"""list-image-referrers-repo-not-found-rejected."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-image-referrers-repo-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListImageReferrers on a nonexistent repository raises RepositoryNotFoundException, while
    a real repository and image return an empty referrers list (positive control)."""
    ecr = ctx.client("ecr")
    missing_repo = ctx.unique_name("sim2real-ecr-missing-")

    code, message = _error(
        lambda: ecr.list_image_referrers(
            repositoryName=missing_repo, subjectId={"imageDigest": "sha256:" + "0" * 64}
        )
    )
    assert code == "RepositoryNotFoundException", code
    assert message == (
        f"The repository with name '{missing_repo}' does not exist in the registry with id '{ctx.account}'"
    ), message

    # Effect-absent: an independent read confirms the repository really does not exist.
    describe_code, describe_message = _error(
        lambda: ecr.describe_repositories(repositoryNames=[missing_repo])
    )
    assert describe_code == "RepositoryNotFoundException", describe_code
    assert describe_message == (
        f"The repository with name '{missing_repo}' does not exist in the registry with id '{ctx.account}'"
    ), describe_message

    # Positive control: a real repository + real image resolves without error.
    repo_name = ctx.unique_name("sim2real-ecr-repo-")
    ecr.create_repository(
        repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    image_id = _push_minimal_image(ecr, repo_name, "v1")

    resp = ecr.list_image_referrers(
        repositoryName=repo_name, subjectId={"imageDigest": image_id["imageDigest"]}
    )
    assert resp["referrers"] == [], resp["referrers"]


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target accepting a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _push_minimal_image(ecr, repo_name, tag):
    """Push a minimal, synthetic Docker v2 schema-2 image directly through the ECR blob-upload
    and PutImage APIs (no docker daemon needed) and return its ImageIdentifier."""
    config_bytes = (
        b'{"architecture":"amd64","os":"linux","config":{},'
        b'"rootfs":{"type":"layers","diff_ids":[]}}'
    )
    layer_bytes = b"sim2real-ecr-behavioral-fidelity-layer-" + repo_name.encode()

    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()

    for blob, digest in ((config_bytes, config_digest), (layer_bytes, layer_digest)):
        upload = ecr.initiate_layer_upload(repositoryName=repo_name)
        ecr.upload_layer_part(
            repositoryName=repo_name,
            uploadId=upload["uploadId"],
            partFirstByte=0,
            partLastByte=len(blob) - 1,
            layerPartBlob=blob,
        )
        ecr.complete_layer_upload(
            repositoryName=repo_name, uploadId=upload["uploadId"], layerDigests=[digest]
        )

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
    result = ecr.put_image(
        repositoryName=repo_name, imageManifest=json.dumps(manifest), imageTag=tag
    )
    return result["image"]["imageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
