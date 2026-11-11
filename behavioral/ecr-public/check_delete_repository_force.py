"""delete-repository-force."""
from __future__ import annotations

import hashlib
import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-repository-force"
GROUP = 'repository-lifecycle'
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRepository with force=true deletes a non-empty repository (images and repo both gone)."""
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)
    _push_test_image(ecr, name, "latest")

    ecr.delete_repository(repositoryName=name, force=True)

    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"The repository with name '{name}' does not exist in the registry with id '{account}'"
    )
    code, message = _err(lambda: ecr.describe_repositories(repositoryNames=[name]))
    assert code == "RepositoryNotFoundException", f"expected repo gone, got {code}"
    assert message == not_found, f"DescribeRepositories message: {message!r}"

    # A mutation against the now-dead name must also fail with the same specific
    # not-found code, not resurrect the repository or silently no-op.
    code_redelete, message_redelete = _err(lambda: ecr.delete_repository(repositoryName=name, force=True))
    assert code_redelete == "RepositoryNotFoundException", (
        f"expected a repeat force-delete of the gone repo to fail not-found, got {code_redelete}"
    )
    assert message_redelete == not_found, f"DeleteRepository message: {message_redelete!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
