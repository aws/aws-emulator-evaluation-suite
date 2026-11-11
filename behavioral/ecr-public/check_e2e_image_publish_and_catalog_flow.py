"""e2e-image-publish-and-catalog-flow."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-image-publish-and-catalog-flow"
GROUP = "e2e"
SERVICES = ["ecr-public"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pushed image tag and repository catalog data are both readable; after the repository is
    deleted, DescribeRepositories and PutRepositoryCatalogData both fail not-found."""
    ecrpublic = _ecrpublic(ctx)
    repo_name = ctx.unique_name("sim2real-ecrpub-e2e-")

    ecrpublic.create_repository(repositoryName=repo_name)

    def _cleanup() -> None:
        try:
            ecrpublic.delete_repository(repositoryName=repo_name, force=True)
        except ecrpublic.exceptions.RepositoryNotFoundException:
            pass

    ctx.on_cleanup(_cleanup)

    config_bytes = json.dumps(
        {"architecture": "amd64", "os": "linux", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}}
    ).encode()
    layer_bytes = os.urandom(128)

    config_digest = _upload_single_part_layer(ctx, repo_name, config_bytes)
    layer_digest = _upload_single_part_layer(ctx, repo_name, layer_bytes)
    manifest_str = _build_manifest(config_digest, len(config_bytes), layer_digest, len(layer_bytes))

    put_resp = ecrpublic.put_image(
        repositoryName=repo_name,
        imageManifest=manifest_str,
        imageManifestMediaType="application/vnd.docker.distribution.manifest.v2+json",
        imageTag="v1",
    )
    image_digest = put_resp["image"]["imageId"]["imageDigest"]

    ecrpublic.put_repository_catalog_data(
        repositoryName=repo_name,
        catalogData={
            "description": "sim2real e2e test repository",
            "aboutText": "About: created by an ecr-public behavioral fidelity check.",
            "usageText": "Usage: docker pull <repo>:v1",
            "architectures": ["x86-64"],
            "operatingSystems": ["Linux"],
        },
    )

    tags_resp = ecrpublic.describe_image_tags(repositoryName=repo_name)
    tag_entries = {t["imageTag"]: t["imageDetail"]["imageDigest"] for t in tags_resp["imageTagDetails"]}
    assert tag_entries.get("v1") == image_digest, f"tag 'v1' -> {tag_entries.get('v1')!r}, expected {image_digest!r}"

    catalog = ecrpublic.get_repository_catalog_data(repositoryName=repo_name)["catalogData"]
    assert catalog["description"] == "sim2real e2e test repository", catalog
    assert catalog["architectures"] == ["x86-64"], catalog
    assert catalog["operatingSystems"] == ["Linux"], catalog

    ecrpublic.delete_repository(repositoryName=repo_name, force=True)

    code, code_msg = _error_code(lambda: ecrpublic.describe_repositories(repositoryNames=[repo_name]))
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {code!r}"
    expected_code_msg = f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
    assert code_msg == expected_code_msg, f"expected message {expected_code_msg!r}, got {code_msg!r}"

    mutate_code, mutate_code_msg = _error_code(
        lambda: ecrpublic.put_repository_catalog_data(
            repositoryName=repo_name, catalogData={"description": "post-delete"}
        )
    )
    assert mutate_code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException, got {mutate_code!r}"
    expected_mutate_code_msg = f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
    assert mutate_code_msg == expected_mutate_code_msg, f"expected message {expected_mutate_code_msg!r}, got {mutate_code_msg!r}"


def _ecrpublic(ctx: Any):
    """A ctx client for ecr-public pinned to us-east-1, the only region that serves it."""
    return ctx.client("ecr-public", region="us-east-1")


def _upload_single_part_layer(ctx: Any, repo_name: str, data: bytes) -> str:
    ecrpublic = _ecrpublic(ctx)
    init = ecrpublic.initiate_layer_upload(repositoryName=repo_name)
    upload_id = init["uploadId"]
    ecrpublic.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    ecrpublic.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest


def _build_manifest(config_digest: str, config_size: int, layer_digest: str, layer_size: int) -> str:
    return json.dumps(
        {
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
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
