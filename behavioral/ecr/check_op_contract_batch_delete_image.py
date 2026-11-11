"""op-contract-batchDeleteImage."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-batchDeleteImage"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDeleteImage deletes the referenced image, reports a per-item ImageNotFound
    failure for a nonexistent digest in the same batch, and raises RepositoryNotFoundException
    for an unknown repository."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx)
    name = repo["repositoryName"]
    pushed = _push_minimal_image(ctx, name, "to-delete", seed=b"batch-delete")

    bogus_digest = "sha256:" + ("0" * 64)
    resp = ecr.batch_delete_image(
        repositoryName=name,
        imageIds=[{"imageTag": "to-delete"}, {"imageDigest": bogus_digest}],
    )
    deleted_digests = {i["imageDigest"] for i in resp["imageIds"]}
    assert deleted_digests == {pushed["digest"]}, (
        f"expected exactly {{{pushed['digest']!r}}} deleted, got {deleted_digests!r}"
    )
    failures = resp["failures"]
    assert len(failures) == 1, f"expected exactly one failure entry, got {failures!r}"
    assert failures[0]["imageId"]["imageDigest"] == bogus_digest, (
        f"failure entry names {failures[0]['imageId']!r}, expected digest {bogus_digest!r}"
    )
    assert failures[0]["failureCode"] == "ImageNotFound", (
        f"expected failureCode ImageNotFound for the bogus digest, got {failures[0]['failureCode']!r}"
    )

    tags_after = ecr.list_images(repositoryName=name)["imageIds"]
    assert all(t.get("imageTag") != "to-delete" for t in tags_after), (
        f"tag 'to-delete' still listed by ListImages after BatchDeleteImage: {tags_after!r}"
    )

    missing_name = ctx.unique_name("sim2real-ecr-missing-")
    code, message = _error(
        lambda: ecr.batch_delete_image(
            repositoryName=missing_name, imageIds=[{"imageTag": "whatever"}]
        )
    )
    assert code == "RepositoryNotFoundException", (
        f"expected RepositoryNotFoundException for a nonexistent repository, got {code!r}"
    )
    expected = (
        f"The repository with name '{missing_name}' does not exist in the registry with id "
        f"'{ctx.account}'"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ctx, **kwargs: Any) -> dict:
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-")
    resp = ecr.create_repository(
        repositoryName=name,
        tags=[{"Key": "sim2real", "Value": CHECK}],
        **kwargs,
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ctx, repo_name: str, data: bytes) -> str:
    ecr = ctx.client("ecr")
    digest = _digest(data)
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
    return digest


def _push_minimal_image(ctx, repo_name: str, tag: str, seed: bytes = b"") -> dict:
    ecr = ctx.client("ecr")
    config_bytes = json.dumps(
        {
            "architecture": "amd64",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": []},
            "seed": seed.decode() if seed else "",
        }
    ).encode()
    layer_bytes = b"sim2real-ecr-layer-" + (seed or b"data") + b"-" * 16
    config_digest = _upload_blob(ctx, repo_name, config_bytes)
    layer_digest = _upload_blob(ctx, repo_name, layer_bytes)
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
    manifest_str = json.dumps(manifest)
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=manifest_str, imageTag=tag
    )
    return {
        "digest": resp["image"]["imageId"]["imageDigest"],
        "manifest": manifest_str,
        "layer_digest": layer_digest,
        "layer_size": len(layer_bytes),
        "config_digest": config_digest,
        "config_size": len(config_bytes),
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
