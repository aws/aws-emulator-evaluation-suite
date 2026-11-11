"""describe-image-signing-status-not-found."""
from __future__ import annotations

import hashlib
import json
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-image-signing-status-not-found"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeImageSigningStatus on a nonexistent image tag raises
    ImageNotFoundException, while the same call on a real pushed image (with no
    signing configured) still succeeds."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-signstatus-")
    ecr.create_repository(repositoryName=repo_name)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    code, message = _error(
        lambda: ecr.describe_image_signing_status(
            repositoryName=repo_name, imageId={"imageTag": "no-such-tag"}
        )
    )
    assert code == "ImageNotFoundException", f"expected ImageNotFoundException, got {code}"
    expected = f"The image with imageId {{imageDigest:'null', imageTag:'no-such-tag'}} does not exist within the repository with name '{repo_name}' in the registry with id '{ctx.account}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: a real pushed image describes signing status without raising, and
    # since no signing configuration matches it, has no signing statuses recorded
    image = _push_minimal_image(ecr, repo_name, "present")
    resp = ecr.describe_image_signing_status(
        repositoryName=repo_name, imageId={"imageTag": "present"}
    )
    assert resp["imageId"]["imageDigest"] == image["imageId"]["imageDigest"], (
        f"expected digest {image['imageId']['imageDigest']}, got {resp['imageId']['imageDigest']}"
    )
    assert resp["signingStatuses"] == [], f"expected no signing statuses, got {resp['signingStatuses']}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
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
