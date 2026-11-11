"""lambda-reads-sse-kms-object-via-customer-key-arn."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "lambda-reads-sse-kms-object-via-customer-key-arn"
GROUP = "arn-resolution"
SERVICES = ["kms", "lambda", "s3"]


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags():
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv():
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx, kind):
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_log_group_if_present(ctx, group):
    """Delete a Lambda log group; the runtime creates it lazily, so it may never exist."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _retry_client_error(fn, *, codes, timeout_s=120.0, interval_s=3.0, description="call"):
    """Call fn() until it stops raising one of `codes`, with a bounded deadline.

    IAM propagation is real and slow: a resource policy naming a just-created role is rejected
    ("invalid principal") until IAM converges, and a service that must assume a brand-new role
    reports it cannot. This retries that window instead of sleeping blind — the deadline is the
    assertion, never a bare time.sleep.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in codes or time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} still failing with {code} after {timeout_s}s"
                ) from exc
        time.sleep(interval_s)


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_role(ctx, trust, inline_policy=None, kind=None):
    """Create an IAM role and register its (policies-then-role) teardown. Returns {name, arn}.

    `trust` is either a service principal string ("lambda.amazonaws.com") or a full trust-policy
    document, which is what the role-to-role AssumeRole checks need.
    """
    iam = ctx.client("iam")
    if isinstance(trust, str):
        doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": trust},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        kind = kind or f"role-{trust.split('.')[0]}"
    else:
        doc = trust
        kind = kind or "role"
    role_name = _xname(ctx, kind)
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(doc),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name):
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_function_active(ctx, name, timeout_s=90.0):
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(ctx, handler_code, role_arn, env=None, timeout=30, memory=128,
                                runtime="python3.12"):
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.

    Registers the function + its auto-created log group for teardown. The inline handler source is
    dedented and aliased to the fixed `lambda_function.lambda_handler` entrypoint.
    """
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 60
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=name))
            ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(ctx, handler_code, permissions=None, env=None, timeout=30, memory=128,
                   runtime="python3.12"):
    """Create a Lambda whose execution role is scoped to `permissions` (IAM statement fragments
    like [{"Action": ["kms:Decrypt"], "Resource": key_arn}]); logs are always allowed.

    Returns {name, arn, role_name, role_arn} — the role identifiers matter here because these
    checks name the execution role as the *principal* in another service's resource policy.
    """
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        resource = perm["Resource"] if isinstance(perm["Resource"], list) else [perm["Resource"]]
        stmt = {"Effect": perm.get("Effect", "Allow"), "Action": actions, "Resource": resource}
        if perm.get("Condition"):
            stmt["Condition"] = perm["Condition"]
        statements.append(stmt)
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    fn = _create_function_with_retry(ctx, handler_code, role["arn"], env, timeout, memory, runtime)
    return {**fn, "role_name": role["name"], "role_arn": role["arn"]}


def _invoke_lambda(ctx, name, payload=None):
    """Invoke a Lambda synchronously; return {status_code[, error], payload|payload_raw}."""
    resp = ctx.client("lambda").invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload or {}).encode(),
    )
    body = resp["Payload"].read()
    result = {"status_code": resp["StatusCode"]}
    if resp.get("FunctionError"):
        result["error"] = resp["FunctionError"]
    try:
        result["payload"] = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        result["payload_raw"] = body.decode("utf-8", errors="replace")
    return result


def _invoke_payload(ctx, name, payload=None):
    """Invoke and return the parsed RESULT PAYLOAD, asserting the handler did not fault.

    A 200 from Invoke proves nothing about the cross-service reference; the payload the handler
    produced after touching the other service is the evidence.
    """
    result = _invoke_lambda(ctx, name, payload)
    assert result.get("status_code") == 200, f"Invoke did not return 200: {result!r}"
    assert "error" not in result, f"handler faulted instead of returning a result: {result!r}"
    assert "payload" in result, f"handler returned non-JSON: {result!r}"
    return result["payload"]


def _delete_bucket(s3, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, kind="bkt"):
    """Create a uniquely-named, region-correct bucket; register empty+delete teardown."""
    s3 = ctx.client("s3")
    name = _xname(ctx, kind)
    params = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(ctx.client("s3"), name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    return name


def _create_key(ctx, description="sim2real-xsvc cross-boundary reference test"):
    """Create a symmetric CMK and register teardown. Returns {id, arn}.

    RESIDUE: a KMS key can only be SCHEDULED for deletion, minimum 7 days, so teardown disables
    the key and schedules deletion at PendingWindowInDays=7 — the key lingers in PendingDeletion
    for a week. That is the AWS contract, not a cleanup leak.
    """
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=description,
        Tags=[{"TagKey": k, "TagValue": v} for k, v in _xsvc_resource_tags().items()],
    )["KeyMetadata"]
    ctx.on_cleanup(
        lambda: ctx.client("kms").schedule_key_deletion(
            KeyId=meta["KeyId"], PendingWindowInDays=7
        )
    )
    ctx.on_cleanup(lambda: ctx.client("kms").disable_key(KeyId=meta["KeyId"]))
    return {"id": meta["KeyId"], "arn": meta["Arn"]}


def _root_allow_statement(account_id):
    """The default key-policy statement that delegates authorization to IAM for the account.

    Every key policy this check writes must keep it: without it PutKeyPolicy is rejected by the
    lockout safety check, and the point of these checks is what happens on TOP of root delegation.
    """
    return {
        "Sid": "EnableIAMUserPermissions",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
        "Action": "kms:*",
        "Resource": "*",
    }


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """S3 records a customer key given by ARN or by bare key id as the full key ARN (aws:kms), and a
    Lambda role holding s3:GetObject and kms:Decrypt reads both objects back byte for byte."""
    s3 = ctx.client("s3")
    key = _create_key(ctx, "sim2real-xsvc s3 sse-kms reference test")
    bucket = _new_bucket(ctx, "ssekms")
    body_by_arn = b"sim2real-xsvc-sse-kms-by-arn"
    body_by_id = b"sim2real-xsvc-sse-kms-by-id"

    s3.put_object(
        Bucket=bucket,
        Key="by-arn.txt",
        Body=body_by_arn,
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=key["arn"],
    )
    # Same key, referenced by bare key id: S3 must resolve it to the same canonical key ARN.
    s3.put_object(
        Bucket=bucket,
        Key="by-id.txt",
        Body=body_by_id,
        ServerSideEncryption="aws:kms",
        SSEKMSKeyId=key["id"],
    )

    for obj_key in ("by-arn.txt", "by-id.txt"):
        head = s3.head_object(Bucket=bucket, Key=obj_key)
        assert head.get("ServerSideEncryption") == "aws:kms", (
            f"{obj_key}: expected ServerSideEncryption aws:kms, got {head.get('ServerSideEncryption')!r}"
        )
        assert head.get("SSEKMSKeyId") == key["arn"], (
            f"{obj_key}: S3 must echo the RESOLVED key ARN {key['arn']!r}, got {head.get('SSEKMSKeyId')!r}"
        )

    code = """
        import os

        import boto3

        s3 = boto3.client("s3")


        def handler(event, context):
            out = {}
            for obj_key in event["keys"]:
                resp = s3.get_object(Bucket=os.environ["BUCKET"], Key=obj_key)
                out[obj_key] = {
                    "body": resp["Body"].read().decode(),
                    "sse": resp.get("ServerSideEncryption"),
                    "sse_key": resp.get("SSEKMSKeyId"),
                }
            return out
    """
    fn = _create_lambda(
        ctx,
        code,
        permissions=[
            {"Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Action": ["kms:Decrypt"], "Resource": key["arn"]},
        ],
        env={"BUCKET": bucket},
    )

    payload = _poll_until(
        lambda: _invoke_payload(ctx, fn["name"], {"keys": ["by-arn.txt", "by-id.txt"]}),
        lambda r: "by-arn.txt" in r and "by-id.txt" in r,
        timeout_s=120.0,
        interval_s=5.0,
        description="the Lambda role reads both SSE-KMS objects",
    )
    assert payload["by-arn.txt"]["body"] == body_by_arn.decode(), payload["by-arn.txt"]
    assert payload["by-id.txt"]["body"] == body_by_id.decode(), payload["by-id.txt"]
    for obj_key in ("by-arn.txt", "by-id.txt"):
        assert payload[obj_key]["sse"] == "aws:kms", payload[obj_key]
        assert payload[obj_key]["sse_key"] == key["arn"], (
            f"{obj_key}: GetObject must report the resolved key ARN to the reader too: {payload[obj_key]!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
