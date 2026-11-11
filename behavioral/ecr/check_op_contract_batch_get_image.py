"""op-contract-batchGetImage."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-batchGetImage"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetImage returns the exact manifest bytes previously pushed for a tag,
    and raises RepositoryNotFoundException for an unknown repository."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx)
    name = repo["repositoryName"]
    pushed = _push_minimal_image(ctx, name, "get-me", seed=b"batch-get")
    assert pushed["digest"] == pushed["expected_digest"], (
        f"PutImage reported digest {pushed['digest']!r} but the pushed manifest's own "
        f"SHA-256 is {pushed['expected_digest']!r} — ECR's imageDigest must be derived "
        "from the manifest bytes, not merely self-consistent across calls"
    )

    resp = ecr.batch_get_image(repositoryName=name, imageIds=[{"imageTag": "get-me"}])
    assert resp["failures"] == [], f"expected no failures, got {resp['failures']!r}"
    assert len(resp["images"]) == 1, f"expected exactly 1 image, got {len(resp['images'])}"
    image = resp["images"][0]
    assert image["imageId"]["imageDigest"] == pushed["digest"], (
        f"BatchGetImage returned digest {image['imageId']['imageDigest']!r}, "
        f"expected {pushed['digest']!r}"
    )
    assert image["imageId"]["imageTag"] == "get-me", (
        f"BatchGetImage returned tag {image['imageId']['imageTag']!r}, expected 'get-me'"
    )
    assert json.loads(image["imageManifest"]) == json.loads(pushed["manifest"]), (
        f"BatchGetImage returned different manifest bytes than PutImage accepted: "
        f"{image['imageManifest'][:300]!r} vs {pushed['manifest'][:300]!r}"
    )
    assert image["imageManifestMediaType"] == "application/vnd.docker.distribution.manifest.v2+json", (
        f"expected mediaType application/vnd.docker.distribution.manifest.v2+json, "
        f"got {image['imageManifestMediaType']!r}"
    )

    missing_name = ctx.unique_name("sim2real-ecr-missing-")
    code, message = _error(
        lambda: ecr.batch_get_image(
            repositoryName=missing_name, imageIds=[{"imageTag": "get-me"}]
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
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
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
        "expected_digest": _digest(manifest_str.encode()),
        "manifest": manifest_str,
        "layer_digest": layer_digest,
        "layer_size": len(layer_bytes),
        "config_digest": config_digest,
        "config_size": len(config_bytes),
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
