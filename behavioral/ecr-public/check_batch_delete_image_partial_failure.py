"""batch-delete-image-partial-failure."""
from __future__ import annotations

import hashlib
import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-delete-image-partial-failure"
GROUP = 'image-data-plane'
SERVICES = ['ecr-public']

def _err(fn):
    """Call fn(), which must fail; return its (Error.Code, Error.Message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"
MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"


def _delete_if_exists(ecr, name):
    """Teardown: force-delete the repository, tolerating one the check already deleted."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
            raise


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_if_exists(ecr, name))
    return name, resp


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repository_name, data: bytes) -> str:
    """Initiate -> UploadPart -> Complete for a single blob; return its sha256 digest."""
    digest = _sha256_digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repository_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repository_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repository_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


def _build_manifest(config_digest, config_size, layer_digest, layer_size) -> str:
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": {"mediaType": CONFIG_MEDIA_TYPE, "size": config_size, "digest": config_digest},
        "layers": [
            {"mediaType": LAYER_MEDIA_TYPE, "size": layer_size, "digest": layer_digest}
        ],
    }
    return json.dumps(manifest, separators=(",", ":"))


def _push_test_image(ecr, repository_name, tag, seed: bytes = b""):
    """Full data-plane push: upload a config blob + a layer blob, build a valid v2 manifest
    referencing both, then PutImage with the tag. Returns (manifest_str, manifest_digest, resp)."""
    config_bytes = json.dumps(
        {"architecture": "amd64", "os": "linux", "seed": seed.hex()}
    ).encode()
    layer_bytes = b"behavioral-fidelity-layer-" + seed + bytes(range(32))
    config_digest = _upload_blob(ecr, repository_name, config_bytes)
    layer_digest = _upload_blob(ecr, repository_name, layer_bytes)
    manifest_str = _build_manifest(
        config_digest, len(config_bytes), layer_digest, len(layer_bytes)
    )
    manifest_digest = _sha256_digest(manifest_str.encode())
    resp = ecr.put_image(
        repositoryName=repository_name,
        imageManifest=manifest_str,
        imageManifestMediaType=MANIFEST_MEDIA_TYPE,
        imageTag=tag,
    )
    return manifest_str, manifest_digest, resp


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDeleteImage reports per-entry outcomes: a valid imageId succeeds while an invalid one in the same batch is reported in failures."""
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)
    tag = "to-delete"
    _, digest, _ = _push_test_image(ecr, name, tag)

    bogus_tag = "this-tag-does-not-exist"
    resp = ecr.batch_delete_image(
        repositoryName=name,
        imageIds=[{"imageTag": tag}, {"imageTag": bogus_tag}],
    )

    failure_tags = [f["imageId"].get("imageTag") for f in resp.get("failures", [])]
    assert bogus_tag in failure_tags, resp

    # The valid tag must not appear among failures (i.e. it succeeded).
    assert tag not in failure_tags, resp

    # Confirm the image is actually gone.
    account = ctx.client("sts").get_caller_identity()["Account"]
    code, message = _err(
        lambda: ecr.describe_images(repositoryName=name, imageIds=[{"imageDigest": digest}])
    )
    assert code == "ImageNotFoundException", f"expected image to be deleted, got {code}"
    assert message == (
        f"The image with imageId {{imageDigest:'{digest}', imageTag:'null'}} does not exist "
        f"within the repository with name '{name}' in the registry with id '{account}'"
    ), f"DescribeImages message: {message!r}"

    ecr.delete_repository(repositoryName=name, force=True)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
