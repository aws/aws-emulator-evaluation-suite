"""create-duplicate-agent-runtime-endpoint-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-duplicate-agent-runtime-endpoint-rejected"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateAgentRuntimeEndpoint under an existing endpoint name is refused with ConflictException and its
    exact message, leaving exactly one endpoint of that name; a differently named endpoint on the same runtime
    reaches READY."""
    bac = ctx.client("bedrock-agentcore-control")
    role_arn = _create_agentcore_execution_role(ctx, "dup")
    name = _safe_name(ctx, "sim2realdup")

    create_resp = _retry_until_role_usable(
        lambda: bac.create_agent_runtime(
            agentRuntimeName=name,
            agentRuntimeArtifact=_create_code_artifact(ctx, "v1"),
            roleArn=role_arn,
            networkConfiguration={"networkMode": "PUBLIC"},
        )
    )

    runtime_id = create_resp["agentRuntimeId"]
    ctx.on_cleanup(lambda: _delete_runtime_when_unblocked(bac, runtime_id))
    _poll_until(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )

    endpoint_name = _safe_name(ctx, "epdup")
    bac.create_agent_runtime_endpoint(agentRuntimeId=runtime_id, name=endpoint_name)
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: bac.delete_agent_runtime_endpoint(
                agentRuntimeId=runtime_id, endpointName=endpoint_name
            )
        )
    )
    _poll_until(
        lambda: bac.get_agent_runtime_endpoint(agentRuntimeId=runtime_id, endpointName=endpoint_name),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )

    # Break: attempt to create a second endpoint with the same name.
    code, message = _error_detail(
        lambda: bac.create_agent_runtime_endpoint(agentRuntimeId=runtime_id, name=endpoint_name)
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected_message = (
        "An endpoint with the specified name already exists. Check the request and try again."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: exactly one endpoint with this name exists on the runtime.
    endpoints = bac.list_agent_runtime_endpoints(agentRuntimeId=runtime_id)["runtimeEndpoints"]
    matching = [e for e in endpoints if e["name"] == endpoint_name]
    assert len(matching) == 1, (
        f"expected exactly 1 endpoint named {endpoint_name!r} on runtime {runtime_id}, "
        f"found {len(matching)}: {matching!r}"
    )

    # Positive control: a differently-named endpoint on the same runtime works.
    other_endpoint_name = _safe_name(ctx, "epother")
    other = bac.create_agent_runtime_endpoint(agentRuntimeId=runtime_id, name=other_endpoint_name)
    ctx.on_cleanup(
        lambda: _safe_delete(
            lambda: bac.delete_agent_runtime_endpoint(
                agentRuntimeId=runtime_id, endpointName=other_endpoint_name
            )
        )
    )
    assert other["endpointName"] == other_endpoint_name, (
        f"expected endpointName {other_endpoint_name!r}, got {other['endpointName']!r}"
    )
    state = _poll_until(
        lambda: bac.get_agent_runtime_endpoint(
            agentRuntimeId=runtime_id, endpointName=other_endpoint_name
        ),
        lambda r: r["status"] != "CREATING",
        timeout_s=120.0,
    )
    assert state["status"] == "READY", f"expected READY, got {state['status']!r}"


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED and returned {result!r}")


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


def _delete_runtime_when_unblocked(bac, runtime_id, timeout_s=180.0, interval_s=5.0):
    """Teardown: endpoint deletes complete asynchronously and DeleteAgentRuntime is refused with
    ConflictException while one remains, so retry that refusal until timeout_s, then raise."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            bac.delete_agent_runtime(agentRuntimeId=runtime_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


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
        bucket = _safe_bucket_name(ctx, "sim2real-dup-code")
        # us-east-1 is region-pinned here only because CreateBucket rejects an explicit
        # LocationConstraint for that region; ctx.region drives every other region.
        if ctx.region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(
                Bucket=bucket,
                CreateBucketConfiguration={"LocationConstraint": ctx.region},
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
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
