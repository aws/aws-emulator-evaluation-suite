"""agent-runtime-code-artifact-requires-existing-s3-object."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Recorded AWS behaviour this check grades:
#   - HeadObject on the not-yet-uploaded key fails with code "404" and message "Not Found" (a HEAD
#     response has no body, so botocore derives both from the HTTP status line).
#   - CreateAgentRuntime naming that missing object is refused synchronously with
#     ValidationException "S3 object not found in bucket", and no runtime of that name is listed.
#   - Once the exact object is uploaded, the byte-identical CreateAgentRuntime reaches READY.
# The execution role needs time to become assumable, so CreateAgentRuntime is retried only on
# ValidationExceptions whose message says "Role validation failed"; the retry never absorbs the
# artifact refusal under test. The bucket is created here, in ctx.region.

CHECK = "agent-runtime-code-artifact-requires-existing-s3-object"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control", "s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AgentCore Runtime whose codeConfiguration names an S3 object that does not exist never
    becomes READY, and the byte-identical create converges to READY once that exact object is
    uploaded."""
    bac = ctx.client("bedrock-agentcore-control")
    s3 = ctx.client("s3")
    role_arn = _create_agentcore_execution_role(ctx)
    bucket = _create_bucket(ctx, s3)

    # The key is chosen now and uploaded LATER, so the same S3 location is first dangling and
    # then valid.
    key = f"sim2real/{CHECK}/deployment_package.zip"
    absent = _error_or_raise(
        lambda: s3.head_object(Bucket=bucket, Key=key),
        subject=f"HeadObject(s3://{bucket}/{key})",
    )
    assert absent["Code"] == "404", (
        f"premise broken: s3://{bucket}/{key} does not read as absent, got code={absent['Code']!r}"
    )
    assert absent["Message"] == "Not Found", (
        f"expected HeadObject on the absent key to report 'Not Found', got {absent['Message']!r}"
    )

    runtime_name = _pattern_safe_name(ctx, "sim2reals3art")
    create_kwargs = {
        "agentRuntimeName": runtime_name,
        "agentRuntimeArtifact": {
            "codeConfiguration": {
                "code": {"s3": {"bucket": bucket, "prefix": key}},
                "runtime": "PYTHON_3_12",
                "entryPoint": ["main.py"],
            }
        },
        "roleArn": role_arn,
        "networkConfiguration": {"networkMode": "PUBLIC"},
    }

    try:
        accepted = _retry_role_validation_only(lambda: bac.create_agent_runtime(**create_kwargs))
    except ClientError as err:
        refusal = err.response["Error"]
    else:
        dangling_id = accepted["agentRuntimeId"]
        ctx.on_cleanup(lambda: _best_effort_delete_runtime(bac, dangling_id))
        raise AssertionError(
            f"CreateAgentRuntime accepted the missing code object s3://{bucket}/{key} "
            f"(runtime {dangling_id!r}); expected a synchronous ValidationException"
        )
    assert refusal["Code"] == "ValidationException", (
        f"expected CreateAgentRuntime to refuse the missing code object s3://{bucket}/{key} "
        f"with ValidationException, got {refusal['Code']!r}"
    )
    assert refusal["Message"] == "S3 object not found in bucket", (
        f"expected the refusal message 'S3 object not found in bucket', got "
        f"{refusal['Message']!r}"
    )
    # Effect absent, via a different operation than the mutation.
    assert not _runtime_named(bac, runtime_name), (
        f"a runtime named {runtime_name!r} is listed despite CreateAgentRuntime being refused"
    )

    # Restore exactly one thing: upload the object the runtime names.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "main.py",
            "def handler(event, context):\n    return {'result': 'sim2real'}\n",
        )
    payload = buf.getvalue()
    s3.put_object(Bucket=bucket, Key=key, Body=payload, Tagging=f"sim2real={CHECK}")
    ctx.on_cleanup(lambda: _safe_delete(lambda: s3.delete_object(Bucket=bucket, Key=key)))
    # Read at the producer side so the restore is proven, not assumed.
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] == len(payload), (
        f"expected s3://{bucket}/{key} to be {len(payload)} bytes, S3 reports "
        f"{head['ContentLength']}"
    )

    # Positive control: the byte-identical CreateAgentRuntime must now converge.
    positive = _retry_role_validation_only(lambda: bac.create_agent_runtime(**create_kwargs))
    runtime_id = positive["agentRuntimeId"]
    ctx.on_cleanup(lambda: _best_effort_delete_runtime(bac, runtime_id))
    final = _poll_until(
        lambda: bac.get_agent_runtime(agentRuntimeId=runtime_id),
        lambda r: r["status"] not in ("CREATING", "UPDATING"),
        "the identical runtime to settle once its code object exists",
        timeout_s=240.0,
    )
    assert final["status"] == "READY", (
        f"the positive control did not converge: status={final['status']!r} "
        f"failureReason={final.get('failureReason')!r} code=s3://{bucket}/{key}"
    )

    # Terminal read at the CONSUMER (the runtime), through a different operation than the
    # mutation: the binding is reported back and the runtime is listed.
    reported = final["agentRuntimeArtifact"]["codeConfiguration"]["code"]["s3"]
    assert reported["bucket"] == bucket, (
        f"expected the runtime to report bucket {bucket!r}, got {reported['bucket']!r}"
    )
    assert reported["prefix"] == key, (
        f"expected the runtime to report prefix {key!r}, got {reported['prefix']!r}"
    )
    assert _runtime_named(bac, runtime_name), (
        f"runtime {runtime_name!r} reached READY but is not listed by ListAgentRuntimes"
    )


def _poll_until(probe, predicate, reason, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {reason}; last value={last!r}")


def _error_or_raise(fn, subject):
    """Return the refusal's Error dict; RAISES on unexpected success, so an accepted call never
    reads as an error-code mismatch."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"{subject} unexpectedly SUCCEEDED; expected it to be refused")


def _retry_role_validation_only(fn, timeout_s=120.0, interval_s=6.0):
    """Scoped deliberately narrowly: only a ValidationException whose message says the ROLE could
    not be validated is retried, so this cannot swallow the artifact-validation refusal that is
    the subject of this check."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return fn()
        except ClientError as err:
            error = err.response["Error"]
            if (
                error["Code"] == "ValidationException"
                and "Role validation failed" in error.get("Message", "")
                and time.monotonic() < deadline
            ):
                last = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"unreachable; last role-validation error={last}")


def _runtime_named(bac, name):
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = bac.list_agent_runtimes(**kwargs)
        for item in page["agentRuntimes"]:
            if item.get("agentRuntimeName") == name:
                return True
        next_token = page.get("nextToken")
        if not next_token:
            return False


def _pattern_safe_name(ctx, prefix):
    """AgentRuntimeName is ^[a-zA-Z][a-zA-Z0-9_]{0,47}$ — no hyphens."""
    raw = ctx.unique_name(prefix)
    safe = "".join(c for c in raw if c.isalnum() or c == "_")
    if not safe[:1].isalpha():
        safe = "a" + safe
    return safe[:48]


def _create_bucket(ctx, s3):
    raw = ctx.unique_name("sim2real-bacs3art-").lower()
    bucket = "".join(c if (c.isalnum() or c == "-") else "-" for c in raw).strip("-")[:63]
    # CreateBucket refuses a LocationConstraint naming us-east-1; that region takes none.
    if ctx.region == "us-east-1":
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
    return bucket


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
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_agentcore_execution_role(ctx):
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-bac-s3art-")[:64]
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
        lambda: _safe_delete(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        )
    )
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _safe_delete(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "NoSuchEntity",
            "NoSuchKey",
        ):
            raise


def _best_effort_delete_runtime(bac, runtime_id):
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        try:
            bac.delete_agent_runtime(agentRuntimeId=runtime_id)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
            time.sleep(5.0)
    bac.delete_agent_runtime(agentRuntimeId=runtime_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
