"""agent-runtime-tag-operations-after-delete-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agent-runtime-tag-operations-after-delete-rejected"
GROUP = "rejected"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource, ListTagsForResource and UntagResource against a deleted AgentRuntime's ARN
    are each refused with NotFoundException, after TagResource and ListTagsForResource
    succeeded while the runtime existed."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_execution_role(ctx)
    runtime_name = _pattern_safe_name(ctx, "sim2realtagdel")

    artifact = _create_code_artifact(ctx)
    created = _retry_until_role_usable(
        lambda: bac.create_agent_runtime(
            agentRuntimeName=runtime_name,
            agentRuntimeArtifact=artifact,
            roleArn=role_arn,
            networkConfiguration={"networkMode": "PUBLIC"},
        )
    )
    runtime_id = created["agentRuntimeId"]
    runtime_arn = created["agentRuntimeArn"]
    runtime_gone = {"confirmed": False}
    ctx.on_cleanup(
        lambda: None if runtime_gone["confirmed"] else _best_effort_delete_runtime(bac, runtime_id)
    )
    logs = ctx.client("logs")
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: logs.delete_log_group(logGroupName=f"/aws/bedrock-agentcore/runtimes/{runtime_id}-DEFAULT")
        )
    )

    state = _poll_until(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=180.0,
    )
    assert state["status"] == "READY", f"unexpected terminal status {state['status']!r}"

    # ---- positive control: TagResource / ListTagsForResource succeed while the runtime exists.
    bac.tag_resource(resourceArn=runtime_arn, tags={"env": "dev"})
    control_tags = bac.list_tags_for_resource(resourceArn=runtime_arn)["tags"]
    assert control_tags == {"env": "dev"}, (
        f"expected {{'env': 'dev'}} on the live runtime, got {control_tags!r}"
    )

    # ---- delete the runtime, and wait for an independent read to confirm it is actually gone.
    bac.delete_agent_runtime(agentRuntimeId=runtime_id)
    code, _ = _poll_error(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        timeout_s=420.0,
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted runtime, got {code!r}"
    )
    runtime_gone["confirmed"] = True

    # ---- the same three tag operations, now refused against the dead ARN.
    expected_message = "Resource was not found"

    tag_code, tag_message = _error_detail(lambda: bac.tag_resource(resourceArn=runtime_arn, tags={"team": "core"}))
    assert tag_code == "NotFoundException", (
        f"expected NotFoundException tagging a deleted runtime, got {tag_code!r}"
    )
    assert tag_message == expected_message, f"expected message {expected_message!r}, got {tag_message!r}"

    list_code, list_message = _error_detail(lambda: bac.list_tags_for_resource(resourceArn=runtime_arn))
    assert list_code == "NotFoundException", (
        f"expected NotFoundException listing tags of a deleted runtime, got {list_code!r}"
    )
    assert list_message == expected_message, f"expected message {expected_message!r}, got {list_message!r}"

    untag_code, untag_message = _error_detail(
        lambda: bac.untag_resource(resourceArn=runtime_arn, tagKeys=["env"])
    )
    assert untag_code == "NotFoundException", (
        f"expected NotFoundException untagging a deleted runtime, got {untag_code!r}"
    )
    assert untag_message == expected_message, f"expected message {expected_message!r}, got {untag_message!r}"


# ===== helpers =====


def _error_detail(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected a ClientError, but the call succeeded")


def _poll_error(probe, timeout_s=180.0, interval_s=5.0):
    """Poll until probe() raises a ClientError; return (code, message). Raises on timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            probe()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for the runtime to become unreadable")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s; last value={last!r}")


def _pattern_safe_name(ctx, prefix):
    """AgentRuntimeName is ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ — no hyphens."""
    raw = ctx.unique_name(prefix)
    safe = "".join(c for c in raw if c.isalnum() or c == "_")
    if not safe[:1].isalpha():
        safe = "a" + safe
    return safe[:48]


def _safe_bucket_name(ctx, prefix):
    raw = ctx.unique_name(prefix).lower()
    cleaned = "".join(c if (c.isalnum() or c == "-") else "-" for c in raw).strip("-")
    return cleaned[:63]


def _safe_delete(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchBucket", "NoSuchKey"):
            raise


def _create_code_artifact(ctx):
    """Uploads a minimal direct-code-deploy .zip to S3 (avoids needing a real ECR image, which
    CreateAgentRuntime actively validates for a containerConfiguration artifact)."""
    s3 = ctx.client("s3")
    bucket = _safe_bucket_name(ctx, "sim2real-tagdel-code")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("main.py", "def handler(event, context):\n    return {'result': 'sim2real'}\n")
    key = "sim2real/v1/deployment_package.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    ctx.on_cleanup(lambda: _safe_delete(lambda: s3.delete_object(Bucket=bucket, Key=key)))

    return {
        "codeConfiguration": {
            "code": {"s3": {"bucket": bucket, "prefix": key}},
            "runtime": "PYTHON_3_12",
            "entryPoint": ["main.py"],
        }
    }


def _empty_and_delete_bucket(s3, bucket):
    try:
        token = None
        while True:
            kwargs = {"Bucket": bucket}
            if token:
                kwargs["ContinuationToken"] = token
            page = s3.list_objects_v2(**kwargs)
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            token = page.get("NextContinuationToken")
            if not token:
                break
        s3.delete_bucket(Bucket=bucket)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_agentcore_execution_role(ctx):
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-bac-tagdel-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _safe_delete(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    )
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _retry_until_role_usable(fn, timeout_s=150.0, interval_s=6.0):
    """A freshly created role's trust policy is eventually consistent; CreateAgentRuntime reports
    that as ValidationException 'Role validation failed'. Retry only that."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code in ("AccessDeniedException", "ValidationException") and (
                "Role validation failed" in message or "role" in message.lower()
            ):
                last = e
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"role never became usable within {timeout_s}s; last error={last}")


def _best_effort_delete_runtime(bac, runtime_id):
    """The body's own DeleteAgentRuntime may still be settling; retry the conflict on a bounded
    deadline, and a prior successful delete (ResourceNotFoundException) is not a leak."""
    deadline = time.monotonic() + 420.0
    while time.monotonic() < deadline:
        try:
            bac.delete_agent_runtime(agentRuntimeId=runtime_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
            time.sleep(5.0)
    bac.delete_agent_runtime(agentRuntimeId=runtime_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
