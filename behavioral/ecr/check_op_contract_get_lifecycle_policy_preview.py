"""op-contract-getLifecyclePolicyPreview."""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getLifecyclePolicyPreview"
GROUP = "error-semantics"
SERVICES = ["ecr"]

_POLICY = {
    "rules": [
        {
            "rulePriority": 1,
            "description": "expire beyond the newest 1",
            "selection": {
                "tagStatus": "any",
                "countType": "imageCountMoreThan",
                "countNumber": 1,
            },
            "action": {"type": "expire"},
        }
    ]
}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLifecyclePolicyPreview before any preview is refused
    LifecyclePolicyPreviewNotFoundException with the exact message; with a keep-newest-1 rule
    over two images, the preview reaches COMPLETE with the older image as its one EXPIRE result."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx)
    name = repo["repositoryName"]
    policy_text = json.dumps(_POLICY)
    ecr.put_lifecycle_policy(repositoryName=name, lifecyclePolicyText=policy_text)
    pushed = _push_minimal_image(ctx, name, "preview-me", seed=b"preview")
    # Push a second, newer image so the repository has 2 images total; the
    # countNumber=1 (imageCountMoreThan) rule keeps only the newest and expires
    # the rest, so the first-pushed image above is the one expected to expire.
    _push_minimal_image(ctx, name, "keep-me", seed=b"keep")

    ecr.start_lifecycle_policy_preview(repositoryName=name)

    def _probe():
        return ecr.get_lifecycle_policy_preview(repositoryName=name)

    final = _poll_until(_probe, lambda r: r["status"] in ("COMPLETE", "FAILED", "EXPIRED"), timeout_s=90.0)
    assert final["status"] == "COMPLETE", f"expected preview status COMPLETE, got {final['status']!r}"
    assert final["summary"]["expiringImageTotalCount"] == 1, (
        f"expected exactly 1 expiring image, got summary={final['summary']!r}"
    )
    results = final["previewResults"]
    assert len(results) == 1, f"expected exactly 1 previewResults entry, got {len(results)}: {results!r}"
    assert results[0]["imageDigest"] == pushed["digest"], (
        f"expected the older pushed image {pushed['digest']!r} to be the one expiring, "
        f"got {results[0]['imageDigest']!r}"
    )
    # The previewResults action type is the ImageActionType enum value, which ECR
    # reports in upper case ("EXPIRE"), unlike the lower-case "expire" used in the
    # lifecycle policy document text itself.
    assert results[0]["action"]["type"] == "EXPIRE", (
        f"expected action.type EXPIRE (ImageActionType enum), got {results[0]['action']!r}"
    )

    fresh_repo = _create_repo(ctx)
    code, message = _error(
        lambda: ecr.get_lifecycle_policy_preview(repositoryName=fresh_repo["repositoryName"])
    )
    assert code == "LifecyclePolicyPreviewNotFoundException", (
        f"expected LifecyclePolicyPreviewNotFoundException for a repo whose preview was never "
        f"started, got {code!r}"
    )
    expected = f"Lifecycle policy preview does not exist for the repository with name '{fresh_repo['repositoryName']}' in the registry with id '{ctx.account}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_repo(ctx, **kwargs: Any) -> dict:
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
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
