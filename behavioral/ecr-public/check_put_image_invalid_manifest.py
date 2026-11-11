"""put-image-invalid-manifest."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-image-invalid-manifest"
GROUP = 'overly-permissive'
SERVICES = ['ecr-public']

CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"
MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"


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


def _build_manifest(config_digest, config_size, layer_digest, layer_size) -> str:
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": {"mediaType": CONFIG_MEDIA_TYPE, "size": config_size, "digest": config_digest},
        "layers": [{"mediaType": LAYER_MEDIA_TYPE, "size": layer_size, "digest": layer_digest}],
    }
    return json.dumps(manifest, separators=(",", ":"))


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutImage with a malformed imageManifest fails with InvalidParameterException and stores nothing,
    while a well-formed manifest on the same repository succeeds; once the repository is deleted, reads
    and further PutImage calls against the name are refused.
    """
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)

    code, code_msg = _err(
        lambda: ecr.put_image(
            repositoryName=name,
            imageManifest="{not-valid-json-at-all",
            imageTag="broken",
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_code_msg = "Invalid parameter at 'ImageManifest' failed to satisfy constraint: 'Invalid JSON syntax'"
    assert code_msg == expected_code_msg, f"expected message {expected_code_msg!r}, got {code_msg!r}"

    described = ecr.describe_images(repositoryName=name)
    assert described["imageDetails"] == [], described

    # --- positive control: PutImage otherwise works on this exact repository -----------------
    config_bytes = json.dumps({"architecture": "amd64", "os": "linux", "repo": name}).encode()
    layer_bytes = b"sim2real-positive-control-layer-" + name.encode() + bytes(range(32))
    config_digest = _upload_blob(ecr, name, config_bytes)
    layer_digest = _upload_blob(ecr, name, layer_bytes)
    manifest_str = _build_manifest(
        config_digest, len(config_bytes), layer_digest, len(layer_bytes)
    )
    manifest_digest = _sha256_digest(manifest_str.encode())
    control = ecr.put_image(
        repositoryName=name,
        imageManifest=manifest_str,
        imageManifestMediaType=MANIFEST_MEDIA_TYPE,
        imageTag="control",
    )["image"]
    assert control["imageId"]["imageDigest"] == manifest_digest, (
        control["imageId"]["imageDigest"], manifest_digest,
    )
    after_control = ecr.describe_images(repositoryName=name)["imageDetails"]
    assert [d["imageDigest"] for d in after_control] == [manifest_digest], (
        f"positive control PutImage did not publish: {after_control}"
    )

    # --- delete proven: gone via an independent read, and no longer mutable ------------------
    ecr.delete_repository(repositoryName=name, force=True)
    not_found, not_found_msg = _err(lambda: ecr.describe_images(repositoryName=name))
    assert not_found == "RepositoryNotFoundException", (
        f"expected RepositoryNotFoundException after delete, got {not_found}"
    )
    expected_not_found_msg = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert not_found_msg == expected_not_found_msg, f"expected message {expected_not_found_msg!r}, got {not_found_msg!r}"
    mutation_after_delete, mutation_after_delete_msg = _err(
        lambda: ecr.put_image(
            repositoryName=name, imageManifest=manifest_str, imageTag="after-delete"
        )
    )
    assert mutation_after_delete == "RepositoryNotFoundException", (
        f"PutImage on a deleted repository should fail RepositoryNotFoundException, "
        f"got {mutation_after_delete}"
    )
    expected_mutation_after_delete_msg = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert mutation_after_delete_msg == expected_mutation_after_delete_msg, f"expected message {expected_mutation_after_delete_msg!r}, got {mutation_after_delete_msg!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
