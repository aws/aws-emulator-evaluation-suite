"""delete-repository-not-empty."""
from __future__ import annotations

import hashlib
import json
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-repository-not-empty"
GROUP = 'repository-lifecycle'
SERVICES = ['ecr-public']

def _err(fn):
    """Call fn(); return (Error.Code, HTTP status, Error.Message) of its ClientError.

    An unexpected success raises rather than returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Message") or "",
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
    repo_tags = kwargs.pop("tags", None) or [{"Key": "sim2real-behavioral-check", "Value": CHECK}]
    resp = ecr.create_repository(repositoryName=name, tags=repo_tags, **kwargs)
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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Non-force DeleteRepository fails RepositoryNotEmptyException while an image is present,
    leaving repository and image intact; it succeeds on an empty repository and once the image
    is removed."""
    ecr = ctx.client("ecr-public")
    control_name, _ = _create_repository(ctx, ecr)
    ecr.delete_repository(repositoryName=control_name)
    control_code, control_status, control_message = _err(
        lambda: ecr.describe_repositories(repositoryNames=[control_name])
    )
    assert control_code == "RepositoryNotFoundException", (
        f"expected control repository gone after unforced delete, got {control_code}"
    )
    assert control_status == 400, f"expected HTTP 400 for the deleted control repository, got {control_status}"
    expected_message = f"The repository with name '{control_name}' does not exist in the registry with id '{ctx.account}'"
    assert control_message == expected_message, f"expected the message {expected_message!r}, got {control_message!r}"

    name, _ = _create_repository(ctx, ecr)
    _, manifest_digest, _ = _push_test_image(ecr, name, "latest")

    code, status, message = _err(lambda: ecr.delete_repository(repositoryName=name))
    assert code == "RepositoryNotEmptyException", f"expected RepositoryNotEmptyException, got {code}"
    assert status == 400, f"expected HTTP 400 for the non-empty delete, got {status}"
    expected_message = f"The repository with name '{name}' in registry with id '{ctx.account}' cannot be deleted because it still contains images"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    described = ecr.describe_repositories(repositoryNames=[name])["repositories"]
    assert described and described[0]["repositoryName"] == name, (
        f"expected repository {name!r} to still exist after the rejected delete, got {described!r}"
    )
    images = ecr.describe_images(
        repositoryName=name, imageIds=[{"imageDigest": manifest_digest}]
    )["imageDetails"]
    assert images and images[0]["imageDigest"] == manifest_digest, (
        f"expected image {manifest_digest!r} to still be present after the rejected delete, got {images!r}"
    )

    batch_resp = ecr.batch_delete_image(
        repositoryName=name, imageIds=[{"imageDigest": manifest_digest}]
    )
    assert not batch_resp.get("failures"), f"expected image deletion to succeed, got {batch_resp!r}"

    ecr.delete_repository(repositoryName=name)
    gone_code, gone_status, gone_message = _err(lambda: ecr.describe_repositories(repositoryNames=[name]))
    assert gone_code == "RepositoryNotFoundException", (
        f"expected repository gone after the now-empty delete, got {gone_code}"
    )
    assert gone_status == 400, f"expected HTTP 400 for the deleted repository, got {gone_status}"
    expected_message = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert gone_message == expected_message, f"expected the message {expected_message!r}, got {gone_message!r}"

    listed = [
        repo["repositoryName"]
        for page in ecr.get_paginator("describe_repositories").paginate()
        for repo in page.get("repositories", [])
    ]
    assert name not in listed, f"expected {name!r} absent from DescribeRepositories after delete, got {listed!r}"

    dead_code, dead_status, message = _err(
        lambda: ecr.put_repository_catalog_data(repositoryName=name, catalogData={"description": CHECK})
    )
    assert dead_code == "RepositoryNotFoundException", (
        f"expected PutRepositoryCatalogData on the deleted repository to be RepositoryNotFoundException, got {dead_code}"
    )
    assert dead_status == 400, f"expected HTTP 400 for PutRepositoryCatalogData on the deleted repository, got {dead_status}"
    expected_message = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
