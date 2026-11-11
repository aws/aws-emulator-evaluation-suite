"""lambda-assumed-role-credential-reads-restricted-bucket."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "lambda-assumed-role-credential-reads-restricted-bucket"
GROUP = "arn-resolution"
SERVICES = ["iam", "lambda", "s3", "sts"]


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"

# The code IAM answers with when a trust policy names an AWS principal it cannot resolve. Not
# InvalidParameterValue, not NoSuchEntity: a trust document that fails referential integrity is
# reported as MALFORMED.
_UNRESOLVED_PRINCIPAL = "MalformedPolicyDocument"


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


def _err_code(fn):
    """Call fn(); return the botocore Error.Code if a ClientError is raised, else None."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _retry_client_error(fn, *, codes, timeout_s=120.0, interval_s=3.0, description="call"):
    """Call fn() until it stops raising one of `codes`, with a bounded deadline.

    IAM propagation is slow: a policy naming a just-created role is rejected until IAM converges.
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
    # IAM resolves every principal a trust policy names; a role created moments earlier is not yet
    # resolvable, so CreateRole is refused with MalformedPolicyDocument for several seconds.
    resp = _retry_client_error(
        lambda: iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(doc),
            Path="/sim2real/",
            Tags=_xsvc_tags_kv(),
        ),
        codes=(_UNRESOLVED_PRINCIPAL,),
        timeout_s=120.0,
        description=f"CreateRole {role_name} once its trust-policy principals resolve",
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


def _delete_log_group(ctx, name):
    """Delete the function's log group, which Lambda creates only once the function logs."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
            ctx.on_cleanup(lambda: _delete_log_group(ctx, name))
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


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role can only sts:AssumeRole reads an S3 object via the assumed role's creds.

    The handler's direct read is denied in the same invocation, which attributes the successful
    read to the assumed ASIA credential; both caller identities are asserted.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_use-resources.html
    """
    s3 = ctx.client("s3")
    account_id = _account_id(ctx)
    bucket = _new_bucket(ctx, "assumed")
    body = b"sim2real-xsvc-assumed-role-body"
    s3.put_object(Bucket=bucket, Key="restricted/data.txt", Body=body)

    # The execution role: logs + AssumeRole only. No s3 action anywhere.
    exec_role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                    ],
                    "Resource": "arn:aws:logs:*:*:*",
                },
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": f"arn:aws:iam::{account_id}:role/sim2real/*",
                },
            ],
        },
    )
    # The target role: trusts the execution role ARN, and is the only holder of s3:GetObject.
    target_role = _create_role(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": exec_role["arn"]},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                }
            ],
        },
        kind="role-target",
    )

    code = """
        import os

        import boto3

        # Region pinned explicitly: this source runs INSIDE Lambda, where the runtime always sets
        # AWS_REGION, so a bare client would already resolve in-region -- but naming it keeps the
        # regional dependency of the call obvious rather than ambient.
        sts = boto3.client("sts", region_name=os.environ["AWS_REGION"])
        s3 = boto3.client("s3", region_name=os.environ["AWS_REGION"])


        def handler(event, context):
            bucket = os.environ["BUCKET"]
            obj_key = "restricted/data.txt"
            out = {"exec_identity": sts.get_caller_identity()["Arn"]}
            try:
                s3.get_object(Bucket=bucket, Key=obj_key)
                out["direct_read"] = "allowed"
            except Exception as exc:
                err = getattr(exc, "response", None) or {}
                out["direct_read"] = err.get("Error", {}).get("Code", type(exc).__name__)
            try:
                creds = sts.assume_role(
                    RoleArn=os.environ["TARGET_ROLE_ARN"],
                    RoleSessionName="sim2real-xsvc-session",
                )["Credentials"]
            except Exception as exc:
                err = getattr(exc, "response", None) or {}
                out["assume_code"] = err.get("Error", {}).get("Code", type(exc).__name__)
                return out
            kw = {
                # Region pinned here too, not just on the ambient clients above: every client built
                # from these kwargs would otherwise inherit whatever the environment supplies, which
                # is an unintended cross-region dependency even though Lambda always sets AWS_REGION.
                "region_name": os.environ["AWS_REGION"],
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            }
            out["access_key_prefix"] = creds["AccessKeyId"][:4]
            out["assumed_identity"] = boto3.client("sts", **kw).get_caller_identity()["Arn"]
            out["body"] = (
                boto3.client("s3", **kw)
                .get_object(Bucket=bucket, Key=obj_key)["Body"]
                .read()
                .decode()
            )
            return out
    """
    fn = _create_function_with_retry(
        ctx,
        code,
        exec_role["arn"],
        env={"BUCKET": bucket, "TARGET_ROLE_ARN": target_role["arn"]},
    )

    payload = _poll_until(
        lambda: _invoke_payload(ctx, fn["name"], {}),
        lambda r: "body" in r,
        timeout_s=180.0,
        interval_s=5.0,
        description="the Lambda assumes the target role and reads the object (IAM propagation)",
    )
    assert payload["body"] == body.decode(), (
        f"the assumed-role credential must return the exact object bytes: {payload!r}"
    )
    # The read cannot have come from the execution role's own permissions.
    assert payload["direct_read"] == "AccessDenied", (
        f"the execution role has no s3 permission and must be denied directly, got "
        f"{payload['direct_read']!r} -- a successful direct read means the role was never enforced"
    )
    # Identity propagation, both hops.
    assert payload["exec_identity"] == (
        f"arn:aws:sts::{account_id}:assumed-role/{exec_role['name']}/{fn['name']}"
    ), (
        f"GetCallerIdentity inside Lambda must report the execution role's assumed-role ARN, got "
        f"{payload['exec_identity']!r}"
    )
    assert payload["assumed_identity"] == (
        f"arn:aws:sts::{account_id}:assumed-role/{target_role['name']}/sim2real-xsvc-session"
    ), (
        f"the assumed session's identity must name the target role and session, got "
        f"{payload['assumed_identity']!r}"
    )
    assert payload["access_key_prefix"] == "ASIA", (
        f"temporary credentials must use the ASIA access-key prefix, got "
        f"{payload['access_key_prefix']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
