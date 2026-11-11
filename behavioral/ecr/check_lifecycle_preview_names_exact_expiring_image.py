"""lifecycle-preview-names-exact-expiring-image."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


DOCKER_MANIFEST_V2 = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG_V1 = "application/vnd.docker.container.image.v1+json"
DOCKER_LAYER_GZIP = "application/vnd.docker.image.rootfs.diff.tar.gzip"


def _create_repo(ecr, ctx, name=None, **kwargs):
    """CreateRepository + register a verified force-delete teardown; returns the repository dict."""
    name = name or ctx.unique_name("sim2real-behav-ecr-repo-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, name))
    return resp["repository"]


def _delete_repo_verified(ecr, name, timeout_s=60):
    ecr.delete_repository(repositoryName=name, force=True)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ecr.describe_repositories(repositoryNames=[name])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
                raise
            return
        time.sleep(1.0)
    raise AssertionError(f"repository {name} still present {timeout_s}s after force delete")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_for_next_epoch_second(*, timeout_s=10.0, interval_s=0.1):
    """Wait until the wall clock enters a new second: imagePushedAt has one-second resolution,
    so the next push then lands a strictly later timestamp."""
    start_second = int(time.time())
    deadline = time.monotonic() + timeout_s
    while int(time.time()) == start_second:
        if time.monotonic() > deadline:
            raise AssertionError("wall clock did not advance to a new second within timeout")
        time.sleep(interval_s)


def _sha256_digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_layer(ecr, repo_name, data):
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
    return json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": DOCKER_MANIFEST_V2,
            "config": {
                "mediaType": DOCKER_CONFIG_V1,
                "size": config_size,
                "digest": config_digest,
            },
            "layers": [
                {"mediaType": DOCKER_LAYER_GZIP, "size": layer_size, "digest": layer_digest}
            ],
        }
    )


def _push_image(ecr, repo_name, tag=None, seed=b"layer-data"):
    """Docker-free push: layer + config blobs via the layer-upload API, then PutImage."""
    layer_digest, layer_size = _upload_layer(ecr, repo_name, seed)
    config_seed = b'{"architecture":"amd64","os":"linux","config":{},"seed":"' + seed + b'"}'
    config_digest, config_size = _upload_layer(ecr, repo_name, config_seed)
    manifest = _build_manifest(layer_digest, layer_size, config_digest, config_size)
    kwargs = {
        "repositoryName": repo_name,
        "imageManifest": manifest,
        "imageManifestMediaType": DOCKER_MANIFEST_V2,
    }
    if tag:
        kwargs["imageTag"] = tag
    return ecr.put_image(**kwargs)["image"]


CHECK = "lifecycle-preview-names-exact-expiring-image"
GROUP = 'lifecycle-policy'
SERVICES = ['ecr']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLifecyclePolicyPreview names the exact image a rule selects (digest, tag, rule priority,
    action): only the oldest prefix match expires, other tag prefixes are untouched, and the
    preview deletes nothing."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ecr, ctx)
    name = repo["repositoryName"]

    # Three images: two matching the rule's tag prefix, one outside it. Spaced so imagePushedAt
    # strictly increases -- the ordering itself is read back from the API, never assumed.
    doomed_a = _push_image(ecr, name, tag="doomed-a", seed=b"lifecycle-seed-a")["imageId"]["imageDigest"]
    _wait_for_next_epoch_second()
    doomed_b = _push_image(ecr, name, tag="doomed-b", seed=b"lifecycle-seed-b")["imageId"]["imageDigest"]
    _wait_for_next_epoch_second()
    keep = _push_image(ecr, name, tag="keep-a", seed=b"lifecycle-seed-keep")["imageId"]["imageDigest"]
    assert len({doomed_a, doomed_b, keep}) == 3, "seeds collided; digests must differ"

    details = ecr.describe_images(repositoryName=name)["imageDetails"]
    pushed_at = {d["imageDigest"]: d["imagePushedAt"] for d in details}
    tags_by_digest = {d["imageDigest"]: set(d.get("imageTags", [])) for d in details}
    assert set(pushed_at) == {doomed_a, doomed_b, keep}, (
        f"describe_images returned {sorted(pushed_at)}, expected the 3 pushed digests"
    )
    assert pushed_at[doomed_a] != pushed_at[doomed_b], (
        f"both doomed images report imagePushedAt={pushed_at[doomed_a]}; oldest-first "
        f"selection is not observable, so the rule engine cannot be graded"
    )
    older, newer = sorted((doomed_a, doomed_b), key=lambda d: pushed_at[d])

    # imageCountMoreThan 1 over tagged images with prefix "doomed" => keep the newest 1,
    # expire the rest. "keep-a" is outside tagPrefixList and must never be selected.
    policy = json.dumps(
        {
            "rules": [
                {
                    "rulePriority": 1,
                    "description": "sim2real: expire all but the newest doomed-prefixed image",
                    "selection": {
                        "tagStatus": "tagged",
                        "tagPrefixList": ["doomed"],
                        "countType": "imageCountMoreThan",
                        "countNumber": 1,
                    },
                    "action": {"type": "expire"},
                }
            ]
        }
    )
    assert len(policy) >= 100, f"lifecyclePolicyText must be >=100 chars, got {len(policy)}"
    put = ecr.put_lifecycle_policy(repositoryName=name, lifecyclePolicyText=policy)
    ctx.on_cleanup(lambda: ecr.delete_lifecycle_policy(repositoryName=name))
    assert put["repositoryName"] == name, f"PutLifecyclePolicy echoed {put}"
    assert json.loads(put["lifecyclePolicyText"])["rules"][0]["rulePriority"] == 1, (
        f"PutLifecyclePolicy did not round-trip the rule: {put['lifecyclePolicyText']}"
    )

    started = ecr.start_lifecycle_policy_preview(repositoryName=name)
    assert started["status"] in ("IN_PROGRESS", "COMPLETE"), (
        f"StartLifecyclePolicyPreview status {started.get('status')!r} is not a modeled "
        f"pre-terminal/terminal value"
    )
    preview = _poll_until(
        lambda: ecr.get_lifecycle_policy_preview(repositoryName=name),
        lambda r: r.get("status") != "IN_PROGRESS",
        timeout_s=180,
        interval_s=3.0,
        description="lifecycle policy preview leaving IN_PROGRESS",
    )
    assert preview["status"] == "COMPLETE", (
        f"preview terminated as {preview['status']}, expected COMPLETE"
    )

    results = preview.get("previewResults", [])
    assert len(results) == 1, (
        f"preview returned {len(results)} results, expected exactly 1 "
        f"(digests: {[r.get('imageDigest') for r in results]}); the rule keeps 1 of 2 "
        f"doomed-prefixed images and must not touch keep-a"
    )
    result = results[0]
    assert result["imageDigest"] == older, (
        f"preview selected {result['imageDigest']}, expected the older doomed image {older} "
        f"(pushed {pushed_at[older]}) rather than {newer} (pushed {pushed_at[newer]})"
    )
    assert set(result.get("imageTags", [])) == tags_by_digest[older], (
        f"preview reported tags {result.get('imageTags')} for {older}, "
        f"describe_images says {sorted(tags_by_digest[older])}"
    )
    assert result["appliedRulePriority"] == 1, (
        f"appliedRulePriority is {result.get('appliedRulePriority')}, expected 1"
    )
    # The policy DOCUMENT spells the action lowercase ("expire"), but the preview RESULT reports
    # the modeled ImageActionType enum, whose only values are EXPIRE and TRANSITION. Real AWS
    # returns {'type': 'EXPIRE'} here: the response is the enum, not an echo of the policy text.
    assert result["action"]["type"] == "EXPIRE", (
        f"action is {result.get('action')}, expected type=EXPIRE (ImageActionType enum)"
    )
    assert result["imagePushedAt"] == pushed_at[older], (
        f"preview imagePushedAt {result['imagePushedAt']} disagrees with describe_images "
        f"{pushed_at[older]}"
    )
    selected = {r["imageDigest"] for r in results}
    assert keep not in selected, f"keep-a ({keep}) was selected despite tagPrefixList=['doomed']"
    assert newer not in selected, f"the newest doomed image ({newer}) was selected"

    summary = preview["summary"]
    assert summary["expiringImageTotalCount"] == 1, (
        f"summary.expiringImageTotalCount is {summary.get('expiringImageTotalCount')}, "
        f"expected exactly 1 and consistent with the {len(results)} previewResults"
    )
    assert json.loads(preview["lifecyclePolicyText"])["rules"][0]["selection"]["tagPrefixList"] == ["doomed"], (
        f"preview echoed a different policy than was put: {preview['lifecyclePolicyText']}"
    )

    # A preview is a dry run: nothing may be deleted.
    still_there = {i["imageDigest"] for i in ecr.list_images(repositoryName=name)["imageIds"]}
    assert still_there == {doomed_a, doomed_b, keep}, (
        f"preview mutated the repository; ListImages now {sorted(still_there)}, "
        f"expected all 3 digests to survive"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
