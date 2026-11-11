"""op-contract-putImageTagMutability."""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-putImageTagMutability"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Once PutImageTagMutability sets IMMUTABLE, a different-content retag raises
    ImageTagAlreadyExistsException and the digest is kept; MUTABLE allows it again, and an
    unknown repository raises RepositoryNotFoundException."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx)
    name = repo["repositoryName"]
    assert repo["imageTagMutability"] == "MUTABLE", (
        f"expected a freshly created repository to default to MUTABLE, got {repo['imageTagMutability']!r}"
    )

    first = _push_minimal_image(ctx, name, "release", seed=b"v1-content")

    resp = ecr.put_image_tag_mutability(repositoryName=name, imageTagMutability="IMMUTABLE")
    assert resp["repositoryName"] == name, (
        f"PutImageTagMutability echoed the wrong repository: expected {name!r}, got {resp['repositoryName']!r}"
    )
    assert resp["imageTagMutability"] == "IMMUTABLE", (
        f"PutImageTagMutability did not echo IMMUTABLE: got {resp['imageTagMutability']!r}"
    )

    # Negative: retagging with different content onto the same tag is refused.
    # The layer uploads succeed before PutImage is refused, so this seed's layers now exist.
    code, message = _error_code(
        lambda: _push_minimal_image(ctx, name, "release", seed=b"v2-rejected-content")
    )
    assert code == "ImageTagAlreadyExistsException", (
        f"expected ImageTagAlreadyExistsException retagging an IMMUTABLE tag with different "
        f"content, got {code!r}"
    )
    expected_message = (
        f"The image tag 'release' already exists in the '{name}' repository and cannot be overwritten "
        f"because the tag is immutable."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    still = ecr.batch_get_image(repositoryName=name, imageIds=[{"imageTag": "release"}])
    assert still["images"][0]["imageId"]["imageDigest"] == first["digest"], (
        f"tag 'release' moved off its original digest despite the refused push: "
        f"expected {first['digest']!r}, got {still['images'][0]['imageId']['imageDigest']!r}"
    )

    # Positive control: switching back to MUTABLE allows retagging onto new content.
    # Use a seed distinct from both v1 and the rejected v2 attempt above, since
    # re-uploading a layer digest that already exists in the repository raises
    # LayerAlreadyExistsException on CompleteLayerUpload.
    ecr.put_image_tag_mutability(repositoryName=name, imageTagMutability="MUTABLE")
    second = _push_minimal_image(ctx, name, "release", seed=b"v3-accepted-content")
    assert second["digest"] != first["digest"], (
        "retagging 'release' after switching back to MUTABLE produced the same digest as the "
        "original push, so the positive control did not exercise a real content change"
    )
    # BatchGetImage is eventually consistent after PutImage: poll (bounded) for the move.
    deadline = time.monotonic() + 60
    while True:
        updated = ecr.batch_get_image(repositoryName=name, imageIds=[{"imageTag": "release"}])
        moved_to = updated["images"][0]["imageId"]["imageDigest"]
        if moved_to == second["digest"] or time.monotonic() >= deadline:
            break
        time.sleep(3)
    assert moved_to == second["digest"], (
        f"tag 'release' did not move to the new digest within 60s after MUTABLE was restored: "
        f"expected {second['digest']!r}, got {moved_to!r}"
    )

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    missing_name = ctx.unique_name("sim2real-ecr-missing-")
    code_missing, message_missing = _error_code(
        lambda: ecr.put_image_tag_mutability(
            repositoryName=missing_name, imageTagMutability="IMMUTABLE"
        )
    )
    assert code_missing == "RepositoryNotFoundException", (
        f"expected RepositoryNotFoundException for PutImageTagMutability on a nonexistent "
        f"repository, got {code_missing!r}"
    )
    expected_missing_message = (
        f"The repository with name '{missing_name}' does not exist in the registry with id "
        f"'{account_id}'"
    )
    assert message_missing == expected_missing_message, f"expected message {expected_missing_message!r}, got {message_missing!r}"


def _error_code(fn):
    """Call fn(); return its botocore Error code. An unexpected SUCCESS raises,
    so a target accepting a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
