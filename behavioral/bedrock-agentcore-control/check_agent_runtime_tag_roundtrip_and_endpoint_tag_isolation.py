"""agent-runtime-tag-roundtrip-and-endpoint-tag-isolation."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agent-runtime-tag-roundtrip-and-endpoint-tag-isolation"
GROUP = "tagging"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource mirrors an AgentRuntime's tags through TagResource's overwrite and
    UntagResource's removal. The DEFAULT endpoint's own ARN keeps a snapshot of the runtime's
    creation-time tags, unaffected by later changes; a named endpoint created with none carries none."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_execution_role(ctx)
    runtime_name = _pattern_safe_name(ctx, "sim2realtagexc")

    artifact = _create_code_artifact(ctx)
    created = _retry_until_role_usable(
        lambda: bac.create_agent_runtime(
            agentRuntimeName=runtime_name,
            agentRuntimeArtifact=artifact,
            roleArn=role_arn,
            networkConfiguration={"networkMode": "PUBLIC"},
            tags={"env": "dev"},
        )
    )
    runtime_id = created["agentRuntimeId"]
    runtime_arn = created["agentRuntimeArn"]
    ctx.on_cleanup(lambda: _best_effort_delete_runtime(bac, runtime_id))
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

    creation_tags = bac.list_tags_for_resource(resourceArn=runtime_arn)["tags"]
    assert creation_tags == {"env": "dev"}, (
        f"expected creation-time tags {{'env': 'dev'}}, got {creation_tags!r}"
    )

    bac.tag_resource(resourceArn=runtime_arn, tags={"env": "prod", "team": "core"})
    tags_after_tag = bac.list_tags_for_resource(resourceArn=runtime_arn)["tags"]
    assert tags_after_tag == {"env": "prod", "team": "core"}, (
        f"expected tags {{'env': 'prod', 'team': 'core'}} after TagResource, got {tags_after_tag!r}"
    )

    bac.untag_resource(resourceArn=runtime_arn, tagKeys=["env"])
    tags_after_untag = bac.list_tags_for_resource(resourceArn=runtime_arn)["tags"]
    assert tags_after_untag == {"team": "core"}, (
        f"expected tags {{'team': 'core'}} after UntagResource(['env']), got {tags_after_untag!r}"
    )

    endpoint_name = _pattern_safe_name(ctx, "sim2realtagexcep")
    bac.create_agent_runtime_endpoint(
        agentRuntimeId=runtime_id, name=endpoint_name, agentRuntimeVersion="1"
    )
    ctx.on_cleanup(lambda: _best_effort_delete_endpoint(bac, runtime_id, endpoint_name))
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: logs.delete_log_group(
                logGroupName=f"/aws/bedrock-agentcore/runtimes/{runtime_id}-{endpoint_name}"
            )
        )
    )
    _poll_until(
        lambda: bac.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint_name),
        lambda r: r["status"] != "CREATING",
        timeout_s=180.0,
    )

    listed = {e["name"]: e for e in bac.list_agent_runtime_endpoints(
        agentRuntimeId=runtime_id
    )["runtimeEndpoints"]}
    assert "DEFAULT" in listed and endpoint_name in listed, (
        f"expected 'DEFAULT' and {endpoint_name!r} in ListAgentRuntimeEndpoints, got {sorted(listed)!r}"
    )

    default_endpoint_arn = listed["DEFAULT"]["agentRuntimeEndpointArn"]
    named_endpoint_arn = listed[endpoint_name]["agentRuntimeEndpointArn"]
    assert default_endpoint_arn != named_endpoint_arn, (
        f"expected DEFAULT and {endpoint_name!r} to have distinct endpoint ARNs, both {default_endpoint_arn!r}"
    )

    # The DEFAULT endpoint is auto-created synchronously inside CreateAgentRuntime, and its own
    # ARN carries a snapshot of the runtime's tags from that moment ({"env": "dev"}) — unaffected
    # by the later TagResource/UntagResource calls made against the runtime's own ARN above.
    default_endpoint_tags = bac.list_tags_for_resource(resourceArn=default_endpoint_arn)["tags"]
    assert default_endpoint_tags == {"env": "dev"}, (
        f"expected the DEFAULT endpoint's own ARN to carry the runtime's creation-time tags "
        f"{{'env': 'dev'}}, got {default_endpoint_tags!r}"
    )

    # The named endpoint, created afterwards with no tags of its own, carries none at all: it
    # does not inherit the runtime's current tags either.
    named_endpoint_tags = bac.list_tags_for_resource(resourceArn=named_endpoint_arn)["tags"]
    assert named_endpoint_tags == {}, (
        f"expected {endpoint_name!r} endpoint's own ARN to carry no tags, got {named_endpoint_tags!r}"
    )

    runtime_tags_unchanged = bac.list_tags_for_resource(resourceArn=runtime_arn)["tags"]
    assert runtime_tags_unchanged == {"team": "core"}, (
        f"expected the runtime's own tags undisturbed by endpoint creation, got {runtime_tags_unchanged!r}"
    )


# ===== helpers =====


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
    """AgentRuntimeName / EndpointName are ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ — no hyphens."""
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
    bucket = _safe_bucket_name(ctx, "sim2real-tagexc-code")
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
    role_name = ctx.unique_name("sim2real-bac-tagexc-")[:64]
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


def _best_effort_delete_endpoint(bac, runtime_id, endpoint_name):
    """A just-created endpoint can still be CREATING when cleanup runs (ConflictException); retry
    on a bounded deadline, and a prior successful delete (ResourceNotFoundException) is not a leak."""
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        try:
            bac.delete_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint_name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
            time.sleep(5.0)
    try:
        bac.delete_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _best_effort_delete_runtime(bac, runtime_id):
    """DeleteAgentRuntime conflicts while an endpoint it owns is still being torn down; retry the
    conflict on a bounded deadline, then let the final attempt raise."""
    deadline = time.monotonic() + 480.0
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
