"""ecr-push-event-triggers-eventbridge-rule."""
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

CHECK = "ecr-push-event-triggers-eventbridge-rule"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "ecr", "ecs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ECR image push emits an 'ECR Image Action' event matching source aws.ecr, delivered via a rule target."""
    ecr = ctx.client("ecr")

    repo_name = ctx.unique_name("sim2real-ecr-pushrepo-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    queue_url, queue_arn = _create_event_queue(ctx, ctx.unique_name("sim2real-ecr-push-eventq-"))
    pattern = {
        "source": ["aws.ecr"],
        "detail-type": ["ECR Image Action"],
        "detail": {"repository-name": [repo_name], "action-type": ["PUSH"]},
    }
    _wire_rule_to_queue(ctx, ctx.unique_name("sim2real-ecr-push-rule-"), pattern, queue_url, queue_arn)

    pushed = _push_minimal_image(ctx, repo_name, "push-me")

    delivered = _poll_for_event(
        ctx,
        queue_url,
        lambda body: (
            body.get("detail-type") == "ECR Image Action"
            and body.get("detail", {}).get("repository-name") == repo_name
        ),
        timeout_s=90,
    )
    assert delivered is not None, "no 'ECR Image Action' PUSH event delivered via EventBridge"
    assert delivered["source"] == "aws.ecr", f"expected source aws.ecr, got {delivered['source']!r}"
    detail = delivered["detail"]
    assert detail["result"] == "SUCCESS", f"expected detail.result SUCCESS, got {detail['result']!r}"
    assert detail["action-type"] == "PUSH", f"expected detail.action-type PUSH, got {detail['action-type']!r}"
    assert detail["repository-name"] == repo_name, (
        f"expected detail.repository-name {repo_name!r}, got {detail['repository-name']!r}"
    )
    assert detail["image-tag"] == "push-me", f"expected detail.image-tag push-me, got {detail['image-tag']!r}"
    assert detail["image-digest"] == pushed["digest"], (
        f"expected detail.image-digest {pushed['digest']!r}, got {detail['image-digest']!r}"
    )


def _push_minimal_image(ctx: Any, repo_name: str, tag: str) -> dict[str, str]:
    """Push a minimal, structurally-valid single-layer image using only the ECR blob-upload API (no docker)."""
    ecr = ctx.client("ecr")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w"):
        pass
    raw_tar = buf.getvalue()
    diff_id = hashlib.sha256(raw_tar).hexdigest()
    layer_bytes = gzip.compress(raw_tar)
    layer_digest = hashlib.sha256(layer_bytes).hexdigest()

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{diff_id}"]},
        "history": [{"created": "2024-01-01T00:00:00Z"}],
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


def _wire_rule_to_queue(
    ctx: Any, rule_name: str, event_pattern: dict[str, Any], queue_url: str, queue_arn: str, target_id: str = "t1"
) -> str:
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(event_pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

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
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}])

    def _cleanup_targets() -> None:
        try:
            events.remove_targets(Rule=rule_name, Ids=[target_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_targets)
    return rule_arn


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
