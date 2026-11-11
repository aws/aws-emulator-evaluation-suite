"""agent-runtime-endpoint-lifecycle-transitions."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agent-runtime-endpoint-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AgentRuntimeEndpoint attaches to a runtime version, becomes routable
    (liveVersion == targetVersion once READY), tracks a newer runtime version
    when updated in place, and is fully removed on delete."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_execution_role(ctx, "are")
    name = _safe_name(ctx, "sim2realare")

    def artifact(tag):
        return _create_code_artifact(ctx, tag)

    create_resp = _retry_until_role_usable(
        lambda: bac.create_agent_runtime(
            agentRuntimeName=name,
            agentRuntimeArtifact=artifact("v1"),
            roleArn=role_arn,
            networkConfiguration={"networkMode": "PUBLIC"},
            tags={"sim2real": CHECK},
        )
    )

    runtime_id = create_resp["agentRuntimeId"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: bac.delete_agent_runtime(agentRuntimeId=runtime_id)))
    _poll_until(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )

    endpoint_name = _safe_name(ctx, "ep")
    bac.create_agent_runtime_endpoint(
        agentRuntimeId=runtime_id, name=endpoint_name, tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: bac.delete_agent_runtime_endpoint(
                agentRuntimeId=runtime_id, endpointName=endpoint_name
            )
        )
    )
    ep_state = _poll_until(
        lambda: bac.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint_name),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )
    assert ep_state["status"] == "READY", f"expected READY, got {ep_state['status']!r}"
    assert ep_state["liveVersion"] == "1", f"expected liveVersion '1', got {ep_state['liveVersion']!r}"
    # targetVersion is only reported while a shift is pending; once READY and
    # converged, AWS omits the key entirely (not an empty string). Its absence IS "caught up with
    # liveVersion", so that is the fallback, not a hardcoded version literal.
    assert ep_state.get("targetVersion", ep_state["liveVersion"]) == ep_state["liveVersion"], (
        f"once READY, targetVersion (if reported) must match liveVersion: {ep_state!r}"
    )

    # Publish a new runtime version, then update the endpoint in place to
    # route to it.
    bac.update_agent_runtime(
        agentRuntimeId=runtime_id,
        agentRuntimeArtifact=artifact("v2"),
        roleArn=role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
    )
    _poll_until(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=120.0,
    )

    bac.update_agent_runtime_endpoint(
        agentRuntimeId=runtime_id, endpointName=endpoint_name, agentRuntimeVersion="2"
    )
    ep_state2 = _poll_until(
        lambda: bac.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint_name),
        lambda r: r["status"] != "UPDATING",
        timeout_s=120.0,
    )
    assert ep_state2["status"] == "READY", f"expected READY, got {ep_state2['status']!r}"
    assert ep_state2["liveVersion"] == "2", (
        f"expected liveVersion '2', got {ep_state2['liveVersion']!r}"
    )
    assert ep_state2.get("targetVersion", ep_state2["liveVersion"]) == ep_state2["liveVersion"], (
        f"once READY, targetVersion (if reported) must match liveVersion: {ep_state2!r}"
    )

    bac.delete_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint_name)
    code, message = _error_detail(
        lambda: bac.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint_name),
        wait_s=90.0,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = f"Agent endpoint with name {endpoint_name} not found for agent {runtime_id}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    endpoints = bac.list_agent_runtime_endpoints(agentRuntimeId=runtime_id)["runtimeEndpoints"]
    assert all(e["name"] != endpoint_name for e in endpoints), (
        f"deleted endpoint {endpoint_name!r} still present in {endpoints!r}"
    )


def _error_detail(fn, *, wait_s=0.0, interval_s=3.0):
    """Return (code, message) of the ClientError fn raises. While fn still succeeds it is
    retried until wait_s elapses; a success at the deadline raises AssertionError."""
    deadline = time.monotonic() + wait_s
    while True:
        try:
            result = fn()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _safe_name(ctx, prefix):
    raw = ctx.unique_name(prefix)
    cleaned = "".join(c for c in raw if c.isalnum() or c == "_")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:48]


def _safe_delete(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


_CODE_BUCKET = {}


def _create_code_artifact(ctx, tag):
    """Uploads a minimal valid Python direct-code-deploy .zip to S3 and
    returns the codeConfiguration agentRuntimeArtifact pointing at it (avoids
    needing a real ECR image, which CreateAgentRuntime actively validates)."""
    s3 = ctx.client("s3")
    if "bucket" not in _CODE_BUCKET:
        bucket = _safe_bucket_name(ctx, "sim2real-are-code")
        if ctx.region == "us-east-1":
            # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={"LocationConstraint": ctx.region},
            )
        s3.put_bucket_tagging(
            Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
        )
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
        _CODE_BUCKET["bucket"] = bucket
    bucket = _CODE_BUCKET["bucket"]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "main.py",
            "def handler(event, context):\n    return {'result': 'sim2real'}\n",
        )
    key = f"sim2real/{tag}/deployment_package.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    ctx.on_cleanup(lambda: _safe_delete(lambda: s3.delete_object(Bucket=bucket, Key=key)))

    return {
        "codeConfiguration": {
            "code": {"s3": {"bucket": bucket, "prefix": key}},
            "runtime": "PYTHON_3_12",
            "entryPoint": ["main.py"],
        }
    }


def _safe_bucket_name(ctx, prefix):
    raw = ctx.unique_name(prefix).lower()
    cleaned = "".join(c if (c.isalnum() or c == "-") else "-" for c in raw)
    cleaned = cleaned.strip("-")
    return cleaned[:63]


def _empty_and_delete_bucket(s3, bucket):
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_agentcore_execution_role(ctx, name_hint):
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-bac-{name_hint}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _retry_until_role_usable(fn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
