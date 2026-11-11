"""ecr-scan-finding-without-rule-target-not-delivered."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ecr-scan-finding-without-rule-target-not-delivered"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "ecr", "ecs"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A matching EventBridge rule with no target attached delivers nothing; wiring a target fixes delivery."""
    ecr = ctx.client("ecr")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    repo_name = ctx.unique_name("sim2real-ecr-notgt-repo-")
    ecr.create_repository(
        repositoryName=repo_name,
        imageScanningConfiguration={"scanOnPush": True},
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    queue_url, queue_arn = _create_event_queue(ctx, ctx.unique_name("sim2real-ecr-notgt-q-"))

    rule_name = ctx.unique_name("sim2real-ecr-notgt-rule-")
    pattern = {
        "source": ["aws.ecr"],
        "detail-type": ["ECR Image Scan"],
        "detail": {"repository-name": [repo_name]},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    # Confirm the blocking condition: the rule genuinely has no targets attached.
    no_targets = events.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert no_targets == [], f"expected a freshly created rule to have no targets, got {no_targets!r}"

    first = _push_minimal_image(ctx, repo_name, "no-target")
    absent = _poll_for_event(
        ctx,
        queue_url,
        lambda body: (
            body.get("detail-type") == "ECR Image Scan"
            and body.get("detail", {}).get("image-digest") == first["digest"]
        ),
        timeout_s=200,
    )
    assert absent is None, "scan-complete event delivered to the queue even though the rule has no target"

    # Positive control: wire the SAME rule to the queue and repeat with a new image.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridge",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    events.put_targets(Rule=rule_name, Targets=[{"Id": "t1", "Arn": queue_arn}])

    def _cleanup_targets() -> None:
        try:
            events.remove_targets(Rule=rule_name, Ids=["t1"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_targets)

    targets_after_wiring = events.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert len(targets_after_wiring) == 1, f"expected exactly 1 target after wiring, got {targets_after_wiring!r}"

    second = _push_minimal_image(ctx, repo_name, "with-target")
    delivered = _poll_for_event(
        ctx,
        queue_url,
        lambda body: (
            body.get("detail-type") == "ECR Image Scan"
            and body.get("detail", {}).get("image-digest") == second["digest"]
        ),
        timeout_s=240,
    )
    assert delivered is not None, "scan-complete event never delivered after wiring the target"
    # Confirmed on real AWS: a synthetic image pushed via the raw layer-upload API (no real OS
    # filesystem) is not analyzable by basic scanning and terminates FAILED, not COMPLETE. What this
    # check exercises is target-wiring, not scan accuracy, so the terminal status this image
    # deterministically produces is the correct oracle, not a guess.
    assert delivered["detail"]["scan-status"] == "FAILED", (
        f"expected scan-status FAILED (the deterministic outcome for this synthetic image), "
        f"got {delivered['detail'].get('scan-status')!r} (full detail={delivered['detail']!r})"
    )
    assert delivered["detail"]["repository-name"] == repo_name, (
        f"expected repository-name {repo_name!r}, got {delivered['detail'].get('repository-name')!r}"
    )


def _push_minimal_image(ctx: Any, repo_name: str, tag: str) -> dict[str, str]:
    """Push a minimal, structurally-valid single-layer image using only the ECR blob-upload API (no docker).

    The layer and config bytes are seeded from ``tag`` so two calls produce genuinely distinct
    digests. Real ECR rejects re-uploading a layer digest that already exists in the repository
    with LayerAlreadyExistsException, and a fixed-content tarball made every call collide.
    """
    ecr = ctx.client("ecr")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        payload = tag.encode()
        info = tarfile.TarInfo(name="tag")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    raw_tar = buf.getvalue()
    diff_id = hashlib.sha256(raw_tar).hexdigest()
    layer_bytes = gzip.compress(raw_tar)
    layer_digest = hashlib.sha256(layer_bytes).hexdigest()

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{diff_id}"]},
        "history": [{"created": "2024-01-01T00:00:00Z", "comment": tag}],
    }
    config_bytes = json.dumps(config).encode()
    config_digest = hashlib.sha256(config_bytes).hexdigest()

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": f"sha256:{config_digest}",
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_bytes),
                "digest": f"sha256:{layer_digest}",
            }
        ],
    }

    for blob, digest_hex in ((config_bytes, config_digest), (layer_bytes, layer_digest)):
        upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
        ecr.upload_layer_part(
            repositoryName=repo_name,
            uploadId=upload_id,
            partFirstByte=0,
            partLastByte=len(blob) - 1,
            layerPartBlob=blob,
        )
        ecr.complete_layer_upload(
            repositoryName=repo_name,
            uploadId=upload_id,
            layerDigests=[f"sha256:{digest_hex}"],
        )

    resp = ecr.put_image(repositoryName=repo_name, imageManifest=json.dumps(manifest), imageTag=tag)
    return {"digest": resp["image"]["imageId"]["imageDigest"], "tag": tag}


def _create_event_queue(ctx: Any, name: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _poll_for_event(ctx: Any, queue_url: str, predicate, timeout_s: float, interval_s: int = 10):
    """Poll the queue until a message matching predicate arrives, or the full timeout elapses.

    Returns the matched, JSON-decoded event body, or None if nothing matched within timeout_s.
    """
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        remaining = max(1, min(interval_s, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=remaining)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if body is not None and predicate(body):
                return body
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
