"""ecr-lifecycle-policy-expiry-event-not-emitted-without-policy."""
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

CHECK = "ecr-lifecycle-policy-expiry-event-not-emitted-without-policy"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "ecr", "ecs"]


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:eventing", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """No repository has a lifecycle policy -> no autonomous DELETE event fires; a manual delete still delivers one."""
    ecr = ctx.client("ecr")
    ctx.client("events")
    ctx.client("sqs")

    repo_name = ctx.unique_name("sim2real-ecr-nolifecycle-repo-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    # Confirm the blocking condition: no lifecycle policy is configured for this repository.
    got = _error(lambda: ecr.get_lifecycle_policy(repositoryName=repo_name))
    want = (
        "LifecyclePolicyNotFoundException",
        f"Lifecycle policy does not exist for the repository with name '{repo_name}' in the registry "
        f"with id '{ctx.account}'",
    )
    assert got == want, f"GetLifecyclePolicy on a repository with no policy raised {got!r}, expected {want!r}"

    queue_url, queue_arn = _create_event_queue(ctx, ctx.unique_name("sim2real-ecr-nolifecycle-q-"))
    pattern = {
        "source": ["aws.ecr"],
        "detail-type": ["ECR Image Action"],
        "detail": {"repository-name": [repo_name], "action-type": ["DELETE"]},
    }
    _wire_rule_to_queue(ctx, ctx.unique_name("sim2real-ecr-nolifecycle-rule-"), pattern, queue_url, queue_arn)

    _push_minimal_image(ctx, repo_name, "keep")
    victim = _push_minimal_image(ctx, repo_name, "victim")

    # No policy is configured, so nothing autonomously expires/deletes either image.
    no_auto_delete = _poll_for_event(
        ctx,
        queue_url,
        lambda body: body.get("detail-type") == "ECR Image Action" and body.get("detail", {}).get("action-type") == "DELETE",
        timeout_s=45,
    )
    assert no_auto_delete is None, "a DELETE event fired even though no lifecycle policy is configured"
    tags_present = {
        img["imageTag"] for img in ecr.list_images(repositoryName=repo_name)["imageIds"] if "imageTag" in img
    }
    assert {"keep", "victim"} <= tags_present, "an image disappeared even though no lifecycle policy is configured"

    # Positive control: the DELETE-event pipeline itself works -- a manual delete on the SAME
    # rule/queue still delivers an 'ECR Image Action' DELETE event. The absence above is because
    # nothing ever triggers a deletion (no policy), not because ECR/EventBridge can't deliver one.
    ecr.batch_delete_image(repositoryName=repo_name, imageIds=[{"imageTag": "victim"}])
    delivered = _poll_for_event(
        ctx,
        queue_url,
        lambda body: (
            body.get("detail-type") == "ECR Image Action"
            and body.get("detail", {}).get("action-type") == "DELETE"
            and body.get("detail", {}).get("image-digest") == victim["digest"]
        ),
        timeout_s=90,
    )
    assert delivered is not None, "manual batch_delete_image never produced a DELETE event via EventBridge"
    assert delivered["detail"]["repository-name"] == repo_name, (
        f"expected repository-name {repo_name!r}, got {delivered['detail']['repository-name']!r}"
    )
    assert delivered["detail"]["result"] == "SUCCESS", f"expected result SUCCESS, got {delivered['detail']['result']!r}"

    # The delete itself must be real, not just the event: an independent read confirms the
    # deleted tag no longer resolves, while the untouched sibling image is still there.
    tags_after_delete = {
        img["imageTag"] for img in ecr.list_images(repositoryName=repo_name)["imageIds"] if "imageTag" in img
    }
    assert tags_after_delete == {"keep"}, f"expected only 'keep' to remain after deleting 'victim', got {tags_after_delete!r}"

    # And confirming the policy really is what's missing: setting one makes GetLifecyclePolicy succeed.
    policy_text = json.dumps(
        {
            "rules": [
                {
                    "rulePriority": 1,
                    "description": "expire old images",
                    "selection": {"tagStatus": "any", "countType": "imageCountMoreThan", "countNumber": 100},
                    "action": {"type": "expire"},
                }
            ]
        }
    )
    ecr.put_lifecycle_policy(repositoryName=repo_name, lifecyclePolicyText=policy_text)
    fetched = ecr.get_lifecycle_policy(repositoryName=repo_name)["lifecyclePolicyText"]
    assert json.loads(fetched) == json.loads(policy_text), (
        f"expected the fetched policy to equal what was put; fetched={fetched!r} put={policy_text!r}"
    )


def _error(fn):
    """(code, message) of a call real AWS refuses. RAISES if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused; it succeeded: {result!r}")


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

    from botocore.exceptions import ClientError

    for blob, digest_hex in ((config_bytes, config_digest), (layer_bytes, layer_digest)):
        # Content is identical across tags (empty tar, fixed history), so a layer pushed for one
        # tag will already exist in the repo by the time the second tag is pushed. ECR treats a
        # re-complete of an existing digest as LayerAlreadyExistsException -- that's fine, the
        # layer is present in the repo either way, which is all put_image needs.
        upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
        ecr.upload_layer_part(
            repositoryName=repo_name,
            uploadId=upload_id,
            partFirstByte=0,
            partLastByte=len(blob) - 1,
            layerPartBlob=blob,
        )
        try:
            ecr.complete_layer_upload(
                repositoryName=repo_name,
                uploadId=upload_id,
                layerDigests=[f"sha256:{digest_hex}"],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "LayerAlreadyExistsException":
                raise

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
    """Poll the queue until a message matching predicate arrives, or the full timeout elapses."""
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
