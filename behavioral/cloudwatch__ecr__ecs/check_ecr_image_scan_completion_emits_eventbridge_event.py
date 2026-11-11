"""ecr-image-scan-completion-emits-eventbridge-event."""
from __future__ import annotations

import base64
import json
import subprocess
import time
from typing import Any

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "ecr-image-scan-completion-emits-eventbridge-event"
GROUP = "event-propagation"
SERVICES = ["cloudwatch", "ecr", "ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "dp:native", "plane:data")
def run(ctx) -> None:
    """A basic ECR image scan-on-push completion is delivered as an 'ECR Image Scan' EventBridge event."""
    require_tools("docker")
    ecr = ctx.client("ecr")
    ctx.client("events")

    repo_name = ctx.unique_name("sim2real-ecr-scanrepo-")
    repo = ecr.create_repository(
        repositoryName=repo_name,
        imageScanningConfiguration={"scanOnPush": True},
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )["repository"]
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    queue_url, queue_arn = _create_event_queue(ctx, ctx.unique_name("sim2real-ecr-scan-eventq-"))
    pattern = {
        "source": ["aws.ecr"],
        "detail-type": ["ECR Image Scan"],
        "detail": {"repository-name": [repo_name]},
    }
    _wire_rule_to_queue(ctx, ctx.unique_name("sim2real-ecr-scan-rule-"), pattern, queue_url, queue_arn)

    pushed = _push_scannable_image(ctx, repo_name, repo["repositoryUri"], "scan-me")

    scanned = _poll_for_event(
        ctx,
        queue_url,
        lambda body: (
            body.get("detail-type") == "ECR Image Scan"
            and body.get("detail", {}).get("image-digest") == pushed["digest"]
        ),
        timeout_s=480,
    )
    assert scanned is not None, "no 'ECR Image Scan' completion event delivered via EventBridge"
    assert scanned["source"] == "aws.ecr", f"expected source 'aws.ecr', got {scanned['source']!r}"
    assert scanned["detail"]["scan-status"] == "COMPLETE", (
        f"expected scan-status 'COMPLETE', got {scanned['detail']['scan-status']!r}"
    )
    assert scanned["detail"]["repository-name"] == repo_name, (
        f"expected repository-name {repo_name!r}, got {scanned['detail']['repository-name']!r}"
    )


_PUBLIC_SCANNABLE_IMAGE = "public.ecr.aws/docker/library/busybox:latest"


def _run_docker(ctx: Any, args: list[str], *, input_str: str | None = None, timeout_s: float = 180.0) -> None:
    """Run a docker subprocess with the run's AWS creds/region in the env; raises with stdout+stderr on failure.

    A hand-built blob-upload layer with no real OS/package data reaches ECR scan-status FAILED,
    not COMPLETE, confirmed against real AWS — so a genuinely scannable image needs a real public
    base image, pulled and pushed via docker rather than assembled by hand.
    """
    ctx.verify_account_safety()
    result = subprocess.run(
        ["docker", *args],
        input=input_str,
        env=ctx.subprocess_env(),
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    assert result.returncode == 0, (
        f"docker {' '.join(args[:1])} failed (rc={result.returncode}): "
        f"stdout={result.stdout[-500:]!r} stderr={result.stderr[-500:]!r}"
    )


def _push_scannable_image(ctx: Any, repo_name: str, repo_uri: str, tag: str) -> dict[str, str]:
    """Pull a real public image and push it into the private repo, so ECR basic scanning has an
    actual OS and package database to identify and can reach a genuine COMPLETE."""
    ecr = ctx.client("ecr")
    auth = ecr.get_authorization_token()["authorizationData"][0]
    username, password = base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)
    registry = auth["proxyEndpoint"]
    dest = f"{repo_uri}:{tag}"

    _run_docker(ctx, ["login", "--username", username, "--password-stdin", registry], input_str=password, timeout_s=30)
    _run_docker(ctx, ["pull", _PUBLIC_SCANNABLE_IMAGE], timeout_s=180)
    _run_docker(ctx, ["tag", _PUBLIC_SCANNABLE_IMAGE, dest], timeout_s=30)
    _run_docker(ctx, ["push", dest], timeout_s=180)

    resp = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": tag}])
    return {"digest": resp["imageDetails"][0]["imageDigest"], "tag": tag}


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
    Runs the FULL timeout when nothing matches, so a None result is a real absence signal.
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
