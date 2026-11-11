"""create-agent-runtime-without-iam-permission-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-agent-runtime-without-iam-permission-denied"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAgentRuntime by a principal with no bedrock-agentcore permissions is refused with
    AccessDeniedException and provisions nothing, while the identical call by a fully
    permissioned principal succeeds (positive control)."""
    client = ctx.client("bedrock-agentcore-control")

    role_arn = _create_deny_role(ctx, "car")
    creds = _assume_role_with_retry(ctx, role_arn)
    restricted = _client_with_creds(ctx, "bedrock-agentcore-control", creds)

    name = _pattern_safe_name(ctx, "sim2realcardenied")
    artifact = _create_code_artifact(ctx, "denied")
    exec_role_arn = _create_agentcore_execution_role(ctx, "carexec")

    code, message = _error_detail(
        lambda: restricted.create_agent_runtime(
            agentRuntimeName=name,
            agentRuntimeArtifact=artifact,
            roleArn=exec_role_arn,
            networkConfiguration={"networkMode": "PUBLIC"},
            tags={"sim2real": CHECK},
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    deny_role_name = role_arn.rsplit("/", 1)[-1]
    expected_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{deny_role_name}/sim2real-behav is not "
        f"authorized to perform: bedrock-agentcore:CreateAgentRuntime on resource: "
        f"arn:aws:bedrock-agentcore:{ctx.region}:{ctx.account}:runtime/* because no "
        f"identity-based policy allows the bedrock-agentcore:CreateAgentRuntime action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


    # Effect absent: no runtime with this name was provisioned.
    assert not _agent_runtime_name_exists(client, name), (
        f"a runtime named {name} exists despite the denied create call"
    )

    # Positive control: the identical call with full permissions succeeds. The
    # execution role's trust policy may not have propagated yet, so retry on
    # role-related rejections only.
    created = _retry_until_role_usable(
        lambda: client.create_agent_runtime(
            agentRuntimeName=name,
            agentRuntimeArtifact=artifact,
            roleArn=exec_role_arn,
            networkConfiguration={"networkMode": "PUBLIC"},
            tags={"sim2real": CHECK},
        )
    )
    runtime_id = created["agentRuntimeId"]
    ctx.on_cleanup(lambda: _best_effort_delete_agent_runtime(client, runtime_id))
    assert created["status"] in ("CREATING", "READY"), (
        f"fully-permissioned create must leave the runtime CREATING or READY, got {created['status']!r}"
    )
    assert _agent_runtime_name_exists(client, name), (
        f"runtime {name!r} was created by the fully-permissioned call but does not appear in "
        "list_agent_runtimes"
    )



# ===== helpers =====
def _error_detail(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an over-permissive target accepting a call AWS refuses must fail loudly rather than surface as a
    mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(
        f"expected the denied principal's call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _pattern_safe_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    safe = "".join(c for c in raw if c.isalnum() or c == "_")
    if not safe[:1].isalpha():
        safe = "c" + safe
    return safe[:48]


def _iam_safe_name(ctx, suffix: str) -> str:
    raw = ctx.unique_name(f"sim2real-behav-{suffix}-")
    safe = "".join(c for c in raw if c.isalnum() or c in "+=,.@_-")
    return safe[:64]


def _create_deny_role(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = _iam_safe_name(ctx, suffix)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _best_effort_delete_role(iam, role_name))
    minimal_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="minimal-no-agentcore", PolicyDocument=json.dumps(minimal_policy)
    )
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _best_effort_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="minimal-no-agentcore")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _assume_role_with_retry(ctx, role_arn: str, timeout_s: float = 60.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")["Credentials"]
        except ClientError as err:
            last_err = err
            time.sleep(3)
    raise AssertionError(f"could not assume restricted role in time: {last_err}")


def _client_with_creds(ctx, service: str, creds):
    return ctx.client(
        service,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _agent_runtime_name_exists(client, name: str) -> bool:
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = client.list_agent_runtimes(**kwargs)
        for item in page.get("agentRuntimes", []):
            if item.get("agentRuntimeName") == name:
                return True
        next_token = page.get("nextToken")
        if not next_token:
            return False


def _best_effort_delete_agent_runtime(client, runtime_id: str) -> None:
    # A runtime still CREATING refuses deletion with ConflictException: retry that code only.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            client.delete_agent_runtime(agentRuntimeId=runtime_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
            time.sleep(2)
    client.delete_agent_runtime(agentRuntimeId=runtime_id)


def _create_agentcore_execution_role(ctx, name_hint: str) -> str:
    iam = ctx.client("iam")
    role_name = _iam_safe_name(ctx, name_hint)
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
    ctx.on_cleanup(lambda: _best_effort_delete_role(iam, role_name))
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _best_effort_detach_policy(iam, role_name, policy_arn))
    return role["Arn"]


def _best_effort_detach_policy(iam, role_name: str, policy_arn: str) -> None:
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retry_until_role_usable(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    # IAM role trust policies are eventually consistent; a freshly created
    # role may not yet be assumable by bedrock-agentcore.amazonaws.com when
    # the create call is first made. Poll the real create call itself until
    # it stops being rejected for role-related reasons.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = err
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


_CODE_BUCKET: dict = {}


def _create_code_artifact(ctx, tag: str) -> dict:
    """Uploads a minimal valid Python direct-code-deploy .zip to S3 and returns
    the codeConfiguration agentRuntimeArtifact pointing at it (avoids needing a
    real ECR image, which CreateAgentRuntime actively validates synchronously)."""
    s3 = ctx.client("s3")
    if "bucket" not in _CODE_BUCKET:
        bucket = _safe_bucket_name(ctx, "sim2real-cardenied-code")
        # us-east-1 is S3's one region where CreateBucket rejects an explicit LocationConstraint;
        # this is not a region pin on the check itself, ctx.region drives everything else.
        if ctx.region == "us-east-1":
            s3.create_bucket(Bucket=bucket)
        else:
            s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
        _CODE_BUCKET["bucket"] = bucket
    bucket = _CODE_BUCKET["bucket"]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("main.py", "def handler(event, context):\n    return {'result': 'sim2real'}\n")
    key = f"sim2real/{tag}/deployment_package.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    ctx.on_cleanup(lambda: _best_effort_delete_s3_object(s3, bucket, key))

    return {
        "codeConfiguration": {
            "code": {"s3": {"bucket": bucket, "prefix": key}},
            "runtime": "PYTHON_3_12",
            "entryPoint": ["main.py"],
        }
    }


def _safe_bucket_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix).lower()
    cleaned = "".join(c if (c.isalnum() or c == "-") else "-" for c in raw)
    return cleaned.strip("-")[:63]


def _best_effort_delete_s3_object(s3, bucket: str, key: str) -> None:
    try:
        s3.delete_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
