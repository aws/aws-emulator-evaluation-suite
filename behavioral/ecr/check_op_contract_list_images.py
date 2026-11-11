"""op-contract-listImages."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listImages"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListImages reflects exactly the tags/digests pushed to a repository, and raises
    RepositoryNotFoundException for an unknown repository."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx)
    name = repo["repositoryName"]
    first = _push_minimal_image(ctx, name, "one", seed=b"list-one")
    second = _push_minimal_image(ctx, name, "two", seed=b"list-two")

    resp = ecr.list_images(repositoryName=name)
    got = {(i.get("imageTag"), i["imageDigest"]) for i in resp["imageIds"]}
    expected = {("one", first["digest"]), ("two", second["digest"])}
    assert got == expected, f"expected ListImages to reflect {expected}, got {got}"
    assert first["digest"] != second["digest"], (
        f"expected distinct pushed images to get distinct digests, both were {first['digest']}"
    )

    missing_name = ctx.unique_name("sim2real-ecr-missing-")
    code, message = _error(lambda: ecr.list_images(repositoryName=missing_name))
    assert code == "RepositoryNotFoundException", (
        f"expected RepositoryNotFoundException for an unknown repository, got {code!r}"
    )
    assert message == (
        f"The repository with name '{missing_name}' does not exist in the registry with id '{ctx.account}'"
    ), message


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ctx, **kwargs: Any) -> dict:
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-")
    tags_kwarg = kwargs.pop("tags", [{"Key": "sim2real", "Value": CHECK}])
    resp = ecr.create_repository(repositoryName=name, tags=tags_kwarg, **kwargs)
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
