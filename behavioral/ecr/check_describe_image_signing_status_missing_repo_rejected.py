"""describe-image-signing-status-missing-repo-rejected."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-image-signing-status-missing-repo-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeImageSigningStatus on a missing repository returns RepositoryNotFoundException; on a
    real image it succeeds with empty signingStatuses, since managed signing is not configured."""
    ecr = ctx.client("ecr")
    missing_repo = ctx.unique_name("sim2real-ecr-missing-")

    code, message = _error(
        lambda: ecr.describe_image_signing_status(
            repositoryName=missing_repo, imageId={"imageTag": "latest"}
        )
    )
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code!r}"
    expected = f"The repository with name '{missing_repo}' does not exist in the registry with id '{ctx.account}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    repo_name = ctx.unique_name("sim2real-ecr-repo-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    image_id = _push_minimal_image(ecr, repo_name, "v1")

    resp = ecr.describe_image_signing_status(repositoryName=repo_name, imageId=image_id)
    assert resp["imageId"]["imageDigest"] == image_id["imageDigest"], (
        f"expected imageDigest {image_id['imageDigest']!r}, got {resp['imageId']['imageDigest']!r}"
    )
    assert resp["signingStatuses"] == [], (
        f"expected no signing statuses for an unsigned image, got {resp['signingStatuses']!r}"
    )


def _error(fn):
    """Return the botocore error (code, message) from fn(); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _push_minimal_image(ecr, repo_name, tag):
    """Push a minimal Docker schema-2 image via the layer-upload and PutImage APIs."""
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
