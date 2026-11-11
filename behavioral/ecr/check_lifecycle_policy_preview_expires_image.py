"""lifecycle-policy-preview-expires-image."""
from __future__ import annotations

import hashlib
import json
import time

from behavioral_harness import tags

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(repositoryName=name, **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]

def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()

def _upload_layer(ecr, repo_name, data):
    """InitiateLayerUpload -> UploadLayerPart -> CompleteLayerUpload; returns (digest, size)."""
    digest = _sha256_digest(data)
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
    return digest, len(data)

def _build_manifest(layer_digest, layer_size, config_digest, config_size):
    manifest = {
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
    return json.dumps(manifest)

def _push_image(ecr, repo_name, tag=None, seed=b"layer-data"):
    """Push a minimally valid Docker Schema-2 image; returns the image dict from PutImage."""
    layer_digest, layer_size = _upload_layer(ecr, repo_name, seed)
    config_seed = b'{"architecture":"amd64","config":{},"seed":"' + seed + b'"}'
    config_digest, config_size = _upload_layer(ecr, repo_name, config_seed)
    manifest_str = _build_manifest(layer_digest, layer_size, config_digest, config_size)
    kwargs = {"repositoryName": repo_name, "imageManifest": manifest_str}
    if tag:
        kwargs["imageTag"] = tag
    return ecr.put_image(**kwargs)["image"]

CHECK = "lifecycle-policy-preview-expires-image"
GROUP = 'lifecycle-policy'
SERVICES = ['ecr']

@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A lifecycle policy preview with imageCountMoreThan=1 reaches COMPLETE and names the older
    image, by digest, as expiring, leaves the newer image alone, and deletes nothing."""
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-behav-ecr-repo-")
    _create_repo(ecr, ctx, name, tags=[{"Key": "sim2real", "Value": CHECK}])
    older_digest = _push_image(ecr, name, tag="v1", seed=b"expire-me-older")["imageId"]["imageDigest"]
    _push_start = time.monotonic()
    _poll_until(
        lambda: time.monotonic() - _push_start,
        lambda elapsed: elapsed >= 2.0,
        timeout_s=5,
        interval_s=0.5,
        description="waiting between pushes for a distinguishable imagePushedAt",
    )
    newer_digest = _push_image(ecr, name, tag="v2", seed=b"keep-me-newer")["imageId"]["imageDigest"]
    assert older_digest != newer_digest, "seeds collided; digests must differ"

    pushed_at = {
        d["imageDigest"]: d["imagePushedAt"]
        for d in ecr.describe_images(repositoryName=name)["imageDetails"]
    }
    assert pushed_at[older_digest] < pushed_at[newer_digest], (
        f"v1 (pushed {pushed_at[older_digest]}) is not older than v2 "
        f"(pushed {pushed_at[newer_digest]}); oldest-first selection is not observable, "
        f"so the rule engine cannot be graded"
    )

    policy_text = (
        '{"rules":[{"rulePriority":1,"description":"keep only newest",'
        '"selection":{"tagStatus":"any","countType":"imageCountMoreThan","countNumber":1},'
        '"action":{"type":"expire"}}]}'
    )
    ecr.put_lifecycle_policy(repositoryName=name, lifecyclePolicyText=policy_text)
    ecr.start_lifecycle_policy_preview(repositoryName=name)

    def probe():
        return ecr.get_lifecycle_policy_preview(repositoryName=name)

    result = _poll_until(
        probe,
        lambda r: r["status"] in ("COMPLETE", "EXPIRED", "FAILED"),
        timeout_s=120,
        interval_s=3,
    )
    assert result["status"] == "COMPLETE", f"expected COMPLETE, got {result['status']}"

    preview_results = result.get("previewResults", [])
    assert len(preview_results) == 1, (
        f"preview returned {len(preview_results)} results, expected exactly 1 "
        f"(digests: {[r.get('imageDigest') for r in preview_results]}); "
        f"imageCountMoreThan=1 over 2 images keeps the newest 1 and expires the rest"
    )
    expiring = preview_results[0]
    assert expiring["imageDigest"] == older_digest, (
        f"preview selected {expiring['imageDigest']} to expire, expected the older image "
        f"{older_digest} (pushed {pushed_at[older_digest]}) rather than the newer image "
        f"{newer_digest} (pushed {pushed_at[newer_digest]})"
    )
    assert expiring["action"]["type"] == "EXPIRE", (
        f"action is {expiring.get('action')}, expected type=EXPIRE (ImageActionType enum)"
    )
    assert result["summary"]["expiringImageTotalCount"] == 1, (
        f"expected exactly one expiring image consistent with the 1 previewResults entry, "
        f"got summary {result['summary']}"
    )

    still_there = {i["imageDigest"] for i in ecr.list_images(repositoryName=name)["imageIds"]}
    assert still_there == {older_digest, newer_digest}, (
        f"a preview is a dry run and must not delete anything; ListImages now "
        f"{sorted(still_there)}, expected both pushed digests to survive"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
