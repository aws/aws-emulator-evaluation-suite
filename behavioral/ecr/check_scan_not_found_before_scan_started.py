"""scan-not-found-before-scan-started."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _client_error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]

def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

def _upload_layer(ecr, repo_name, data):
    """InitiateLayerUpload -> UploadLayerPart -> CompleteLayerUpload; returns (digest, size)."""
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
    return json.dumps(manifest)

def _push_image(ecr, repo_name, tag=None, seed=b"layer-data"):
    """Push a minimally valid Docker Schema-2 image; returns the image dict from PutImage."""
    layer_digest, layer_size = _upload_layer(ecr, repo_name, seed)
    config_seed = b'{"architecture":"amd64","config":{},"seed":"' + seed + b'"}'
    config_digest, config_size = _upload_layer(ecr, repo_name, config_seed)
    manifest_str = _build_manifest(layer_digest, layer_size, config_digest, config_size)
    kwargs = {"repositoryName": repo_name, "imageManifest": manifest_str}
    if tag:
        kwargs["imageTag"] = tag
    return ecr.put_image(**kwargs)["image"]

CHECK = "scan-not-found-before-scan-started"
GROUP = 'error-semantics'
SERVICES = ['ecr']

@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeImageScanFindings on an image that has never been scanned MUST fail
    with ScanNotFoundException -- distinct from an ImageNotFoundException, since the
    image itself exists."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name, imageScanningConfiguration={"scanOnPush": False})
    image = _push_image(ecr, name, tag="v1", seed=b"never-scanned")
    digest = image["imageId"]["imageDigest"]

    code, message = _client_error(
        lambda: ecr.describe_image_scan_findings(
            repositoryName=name, imageId={"imageDigest": digest}
        )
    )
    assert code == "ScanNotFoundException", f"expected ScanNotFoundException, got {code}"
    assert message == (
        f"Image scan does not exist for the image with '{{imageDigest:'{digest}', imageTag:'null'}}' "
        f"in the repository with name '{name}' in the registry with id '{ctx.account}'"
    ), message

    # Contrast control: an imageId that was never pushed to this repo must raise the
    # *different* ImageNotFoundException, not the same ScanNotFoundException -- proving
    # the target actually distinguishes "image absent" from "image present, never scanned"
    # rather than returning one error code for both.
    never_pushed_digest = _sha256_digest(b"never-pushed-image")
    missing_code, missing_message = _client_error(
        lambda: ecr.describe_image_scan_findings(
            repositoryName=name, imageId={"imageDigest": never_pushed_digest}
        )
    )
    assert missing_code == "ImageNotFoundException", (
        f"expected ImageNotFoundException for a never-pushed digest, got {missing_code}"
    )
    assert missing_message == (
        f"The image with imageId {{imageDigest:'{never_pushed_digest}', imageTag:'null'}} does not "
        f"exist within the repository with name '{name}' in the registry with id '{ctx.account}'"
    ), missing_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
