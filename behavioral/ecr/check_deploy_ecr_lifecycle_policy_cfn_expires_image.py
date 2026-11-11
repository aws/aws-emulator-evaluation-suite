"""deploy-ecr-lifecycle-policy-cfn-expires-image."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time

from behavioral_harness import tags

CHECK = "deploy-ecr-lifecycle-policy-cfn-expires-image"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A lifecycle policy PUT through the ECR API on a CloudFormation-deployed repository is stored
    verbatim, and its preview flags the older of two pushed images EXPIRE while keeping the newer
    one -- the policy is evaluated, not just persisted as opaque text."""
    ecr = ctx.client("ecr")
    cfn = ctx.client("cloudformation")

    repo_name = ctx.unique_name("sim2real-ecr-lp-")
    stack_name = ctx.unique_name("sim2real-ecr-lp-stack-")
    lifecycle_policy = {
        "rules": [
            {
                "rulePriority": 1,
                "description": "sim2real behavioral fidelity check: retain only the "
                "newest image in this repository, expiring older ones",
                "selection": {
                    "tagStatus": "any",
                    "countType": "imageCountMoreThan",
                    "countNumber": 1,
                },
                "action": {"type": "expire"},
            }
        ]
    }
    template = json.dumps(
        {
            "Resources": {
                "Repo": {
                    "Type": "AWS::ECR::Repository",
                    "Properties": {
                        "RepositoryName": repo_name,
                        "EmptyOnDelete": True,
                    },
                }
            }
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    # The lifecycle policy is attached via PutLifecyclePolicy to the CloudFormation-deployed
    # repository (the deploy-via-CFN, manage-via-API pattern).
    ecr.put_lifecycle_policy(
        repositoryName=repo_name, lifecyclePolicyText=json.dumps(lifecycle_policy)
    )

    stored = ecr.get_lifecycle_policy(repositoryName=repo_name)
    assert json.loads(stored["lifecyclePolicyText"]) == lifecycle_policy, (
        f"stored lifecycle policy {stored['lifecyclePolicyText']} does not match "
        f"what was PUT: {json.dumps(lifecycle_policy)}"
    )

    older_image = _push_minimal_image(ctx, repo_name, "v1")
    older_digest = older_image["imageId"]["imageDigest"]
    older_pushed_at = ecr.describe_images(
        repositoryName=repo_name, imageIds=[{"imageDigest": older_digest}]
    )["imageDetails"][0]["imagePushedAt"]

    # The lifecycle rule keeps only the single newest image, so the second push must
    # be distinguishable as newer. ECR's imagePushedAt has whole-second granularity, so
    # wait -- bounded, against the real timestamp AWS already recorded for the older
    # image -- until a fresh push is guaranteed to land in a later second, rather than
    # assuming a fixed delay is long enough.
    _poll_until(
        lambda: time.time(),
        lambda now: now - older_pushed_at.timestamp() >= 1.0,
        timeout_s=10.0,
        interval_s=0.2,
    )

    newer_image = _push_minimal_image(
        ctx, repo_name, "v2", config_extra={"comment": "newer"}
    )
    newer_digest = newer_image["imageId"]["imageDigest"]
    newer_pushed_at = ecr.describe_images(
        repositoryName=repo_name, imageIds=[{"imageDigest": newer_digest}]
    )["imageDetails"][0]["imagePushedAt"]
    assert newer_pushed_at > older_pushed_at, (
        f"expected v2 imagePushedAt ({newer_pushed_at}) after v1's "
        f"({older_pushed_at}); got a tie or the reverse order"
    )
    pushed_digest = older_digest

    ecr.start_lifecycle_policy_preview(repositoryName=repo_name)

    preview = _poll_until(
        lambda: ecr.get_lifecycle_policy_preview(repositoryName=repo_name),
        lambda resp: resp["status"] in ("COMPLETE", "FAILED", "EXPIRED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert preview["status"] == "COMPLETE", f"expected COMPLETE, got {preview}"

    matched = [
        r for r in preview["previewResults"] if r["imageDigest"] == pushed_digest
    ]
    assert len(matched) == 1, (
        f"expected exactly one preview result for the older image {pushed_digest}, "
        f"got {preview['previewResults']}"
    )
    assert matched[0]["action"]["type"] == "EXPIRE", (
        f"expected the older image to be flagged EXPIRE, got {matched[0]}"
    )

    newer_matched = [
        r for r in preview["previewResults"] if r["imageDigest"] == newer_digest
    ]
    assert not (newer_matched and newer_matched[0]["action"]["type"] == "EXPIRE"), (
        f"expected the newer image to be kept, not flagged EXPIRE: {newer_matched}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last={last}")


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _upload_blob(ecr, repo_name: str, blob_bytes: bytes) -> tuple[str, int]:
    digest = "sha256:" + hashlib.sha256(blob_bytes).hexdigest()
    avail = ecr.batch_check_layer_availability(
        repositoryName=repo_name, layerDigests=[digest]
    )
    if avail["layers"] and avail["layers"][0]["layerAvailability"] == "AVAILABLE":
        return digest, avail["layers"][0]["layerSize"]
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob_bytes) - 1,
        layerPartBlob=blob_bytes,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest, len(blob_bytes)


def _push_minimal_image(ctx, repo_name: str, tag: str, config_extra: dict | None = None):
    ecr = ctx.client("ecr")

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w"):
        pass
    tar_bytes = tar_buf.getvalue()
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    gz_bytes = gz_buf.getvalue()

    layer_digest, layer_size = _upload_blob(ecr, repo_name, gz_bytes)
    diff_id = "sha256:" + hashlib.sha256(tar_bytes).hexdigest()

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "history": [{"created": "2024-01-01T00:00:00Z"}],
    }
    if config_extra:
        config.update(config_extra)
    config_bytes = json.dumps(config).encode("utf-8")
    config_digest, config_size = _upload_blob(ecr, repo_name, config_bytes)

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
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=json.dumps(manifest), imageTag=tag
    )
    return resp["image"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
