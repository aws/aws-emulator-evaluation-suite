"""describe-images-not-found."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-images-not-found"
GROUP = 'error-semantics'
SERVICES = ['ecr-public']

_MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
_CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
_LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"

def _err(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_repository(ctx, ecr, name=None, **kwargs):
    """CreateRepository, registering a force-delete teardown. Returns (name, response)."""
    name = name or ctx.unique_name("sim2real-behav-ecrpub-repo-")
    kwargs.setdefault("tags", [{"Key": "sim2real", "Value": CHECK}])
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: _delete_repository_if_present(ecr, name))
    return name, resp


def _delete_repository_if_present(ecr, name):
    """Teardown: force-delete the repository, tolerating one the check already deleted."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


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


def _push_image(ecr, repository_name, tag):
    """Push a real, minimal image; return its imageDigest."""
    config_bytes = json.dumps({"architecture": "amd64", "os": "linux"}).encode()
    layer_bytes = b"sim2real-behav-ecrpub-layer-" + repository_name.encode()
    config_digest = _upload_blob(ecr, repository_name, config_bytes)
    layer_digest = _upload_blob(ecr, repository_name, layer_bytes)
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": _MANIFEST_MEDIA_TYPE,
            "config": {"mediaType": _CONFIG_MEDIA_TYPE, "size": len(config_bytes), "digest": config_digest},
            "layers": [{"mediaType": _LAYER_MEDIA_TYPE, "size": len(layer_bytes), "digest": layer_digest}],
        },
        separators=(",", ":"),
    )
    resp = ecr.put_image(
        repositoryName=repository_name,
        imageManifest=manifest,
        imageManifestMediaType=_MANIFEST_MEDIA_TYPE,
        imageTag=tag,
    )
    return resp["image"]["imageId"]["imageDigest"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeImages for an imageId the repository never held is refused ImageNotFoundException
    with the exact message while the pushed image is described; after DeleteRepository, reads and
    a repeat delete are refused RepositoryNotFoundException."""
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)
    pushed_digest = _push_image(ecr, name, tag="v1")
    bogus_digest = "sha256:" + "3" * 64

    # Positive control: the real, just-pushed image resolves without error.
    control = ecr.describe_images(repositoryName=name, imageIds=[{"imageDigest": pushed_digest}])
    assert [d["imageDigest"] for d in control["imageDetails"]] == [pushed_digest], (
        f"expected the pushed image {pushed_digest!r} to resolve, got {control['imageDetails']!r}"
    )

    code, code_msg = _err(
        lambda: ecr.describe_images(repositoryName=name, imageIds=[{"imageDigest": bogus_digest}])
    )
    assert code == "ImageNotFoundException", f"expected ImageNotFoundException, got {code}"
    expected_code_msg = f"The image with imageId {{imageDigest:'{bogus_digest}', imageTag:'null'}} does not exist within the repository with name '{name}' in the registry with id '{ctx.account}'"
    assert code_msg == expected_code_msg, f"expected message {expected_code_msg!r}, got {code_msg!r}"

    # force=True: the repository still holds the image pushed for the positive control above,
    # and real AWS refuses a non-forced DeleteRepository on a non-empty repository
    # (RepositoryNotEmptyException).
    ecr.delete_repository(repositoryName=name, force=True)

    # The delete is real: an independent read confirms the repository -- and everything pushed
    # into it -- is gone, and a second delete of the same id also fails rather than no-op success.
    gone_code, gone_code_msg = _err(lambda: ecr.describe_images(repositoryName=name))
    assert gone_code == "RepositoryNotFoundException", (
        f"expected RepositoryNotFoundException reading a deleted repository, got {gone_code}"
    )
    expected_gone_code_msg = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert gone_code_msg == expected_gone_code_msg, f"expected message {expected_gone_code_msg!r}, got {gone_code_msg!r}"
    redelete_code, redelete_code_msg = _err(lambda: ecr.delete_repository(repositoryName=name))
    assert redelete_code == "RepositoryNotFoundException", (
        f"expected a second delete of the same repository to fail with RepositoryNotFoundException, "
        f"got {redelete_code}"
    )
    expected_redelete_code_msg = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert redelete_code_msg == expected_redelete_code_msg, f"expected message {expected_redelete_code_msg!r}, got {redelete_code_msg!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
