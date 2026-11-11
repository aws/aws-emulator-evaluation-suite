"""image-push-lifecycle."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-push-lifecycle"
GROUP = 'image-data-plane'
SERVICES = ['ecr-public']

CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"
MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"


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


def _error_code(fn):
    """Call fn(); return its ClientError (code, HTTP status, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response["Error"].get("Message") or "",
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full data-plane push: Initiate/Upload/CompleteLayerUpload -> PutImage -> DescribeImages/DescribeImageTags
    reflect the pushed digest and tag -> DeleteRepository -> an independent read and a mutation against the
    dead repository both fail with RepositoryNotFoundException."""
    ecr = ctx.client("ecr-public")
    name, _ = _create_repository(ctx, ecr)
    tag = "v1"

    manifest_str, expected_digest, put_resp = _push_test_image(ecr, name, tag)
    image = put_resp["image"]
    assert image["repositoryName"] == name, (
        f"PutImage repositoryName: expected {name!r}, got {image['repositoryName']!r}"
    )
    assert image["imageId"]["imageTag"] == tag, (
        f"PutImage imageTag: expected {tag!r}, got {image['imageId']['imageTag']!r}"
    )
    assert image["imageId"]["imageDigest"] == expected_digest, (
        f"PutImage imageDigest: expected {expected_digest!r}, got {image['imageId']['imageDigest']!r}"
    )

    described = ecr.describe_images(repositoryName=name)
    digests = [d["imageDigest"] for d in described["imageDetails"]]
    assert expected_digest in digests, f"DescribeImages: expected digest {expected_digest!r} in {digests!r}"
    matching = next(d for d in described["imageDetails"] if d["imageDigest"] == expected_digest)
    assert tag in matching.get("imageTags", []), (
        f"DescribeImages: expected tag {tag!r} on the pushed digest, got {matching.get('imageTags')!r}"
    )

    tags_resp = ecr.describe_image_tags(repositoryName=name)
    tag_entries = {t["imageTag"]: t["imageDetail"]["imageDigest"] for t in tags_resp["imageTagDetails"]}
    assert tag_entries.get(tag) == expected_digest, (
        f"DescribeImageTags: expected {tag!r} -> {expected_digest!r}, got {tag_entries!r}"
    )

    ecr.delete_repository(repositoryName=name, force=True)

    # The delete is a consequence, not just a 200: an independent read at the repository
    # reports it gone, and a mutation against the dead id is refused the same way.
    read_code, read_status, read_code_msg = _error_code(lambda: ecr.describe_images(repositoryName=name))
    assert read_code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {read_code}"
    assert read_status == 400, f"expected HTTP 400 on DescribeImages of the deleted repository, got {read_status}"
    expected_message = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert read_code_msg == expected_message, f"expected the message {expected_message!r}, got {read_code_msg!r}"

    # Gone beat 2: the paginated repository listing no longer contains the name.
    listed = [
        r["repositoryName"]
        for page in ecr.get_paginator("describe_repositories").paginate()
        for r in page["repositories"]
    ]
    assert name not in listed, "the deleted repository is still listed by DescribeRepositories"

    mutate_code, mutate_status, mutate_code_msg = _error_code(lambda: ecr.put_image(
        repositoryName=name,
        imageManifest=manifest_str,
        imageManifestMediaType=MANIFEST_MEDIA_TYPE,
        imageTag=tag,
    ))
    assert mutate_code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {mutate_code}"
    assert mutate_status == 400, f"expected HTTP 400 on PutImage to the deleted repository, got {mutate_status}"
    expected_message = f"The repository with name '{name}' does not exist in the registry with id '{ctx.account}'"
    assert mutate_code_msg == expected_message, f"expected the message {expected_message!r}, got {mutate_code_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
