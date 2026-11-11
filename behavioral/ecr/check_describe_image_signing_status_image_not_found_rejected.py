"""describe-image-signing-status-image-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-image-signing-status-image-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeImageSigningStatus for an image tag that was never pushed returns
    ImageNotFoundException; the same call for an image that really exists succeeds."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx)
    pushed = _push_image(ctx, repo["repositoryName"], tag="v1")

    code, code_msg = _error(
        lambda: ecr.describe_image_signing_status(
            repositoryName=repo["repositoryName"], imageId={"imageTag": "never-pushed"}
        )
    )
    assert code == "ImageNotFoundException", f"expected ImageNotFoundException, got {code!r}"
    expected_msg = (
        f"The image with imageId {{imageDigest:'null', imageTag:'never-pushed'}} does not exist within the "
        f"repository with name '{repo['repositoryName']}' in the registry with id '{ctx.account}'"
    )
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

    # positive control: the image that was actually pushed resolves without error and, since
    # no signing configuration matches it, has no signing statuses recorded
    resp = ecr.describe_image_signing_status(
        repositoryName=repo["repositoryName"],
        imageId={"imageDigest": pushed["imageId"]["imageDigest"]},
    )
    assert resp["signingStatuses"] == [], (
        f"expected no signing statuses for an unsigned image, got {resp['signingStatuses']!r}"
    )


import hashlib
import json
import time

_MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
_CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
_LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ctx, **kwargs):
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


def _upload_blob(ecr, repo_name, data):
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
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


def _push_image(ctx, repo_name, tag=None):
    ecr = ctx.client("ecr")
    unique = f"{repo_name}-{time.time_ns()}"
    config_bytes = json.dumps(
        {"architecture": "amd64", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}, "unique": unique}
    ).encode()
    layer_bytes = f"sim2real-ecr-layer-{unique}".encode()
    config_digest = _upload_blob(ecr, repo_name, config_bytes)
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": _MANIFEST_MEDIA_TYPE,
        "config": {"mediaType": _CONFIG_MEDIA_TYPE, "size": len(config_bytes), "digest": config_digest},
        "layers": [{"mediaType": _LAYER_MEDIA_TYPE, "size": len(layer_bytes), "digest": layer_digest}],
    }
    kwargs = {"repositoryName": repo_name, "imageManifest": json.dumps(manifest)}
    if tag:
        kwargs["imageTag"] = tag
    return ecr.put_image(**kwargs)["image"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
