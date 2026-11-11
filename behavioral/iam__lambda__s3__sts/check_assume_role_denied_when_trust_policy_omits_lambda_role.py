"""assume-role-denied-when-trust-policy-omits-lambda-role."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "assume-role-denied-when-trust-policy-omits-lambda-role"
GROUP = "overly-permissive"
SERVICES = ["iam", "lambda", "s3", "sts"]


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"

# The code IAM answers with when a trust policy names an AWS principal it cannot resolve. Not
# InvalidParameterValue, not NoSuchEntity: a trust document that fails referential integrity is
# reported as MALFORMED.
_UNRESOLVED_PRINCIPAL = "MalformedPolicyDocument"


def _budget_s(ctx, cap_s):
    """A poll's timeout, bounded by the runner's remaining time so the poll fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


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
    Covers IAM propagation, e.g. a just-created role not yet valid as a principal."""
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
    `trust` is a service principal string or a full trust-policy document."""
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
    # IAM RESOLVES every principal a trust policy names, and a role created moments earlier is not
    # yet resolvable, so CreateRole is refused with MalformedPolicyDocument / "Invalid principal in
    # policy: \"AWS\":\"<arn>\"" for several seconds. Retry that window only; an ARN that names
    # nothing is refused forever, which the rejection leg in run() asserts.
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
        timeout_s=_budget_s(ctx, timeout_s),
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(ctx, handler_code, role_arn, env=None, timeout=30, memory=128,
                                runtime="python3.12"):
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.
    Registers the function and its log group for teardown."""
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
            ctx.on_cleanup(
                lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
            )
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
    """Create a Lambda whose execution role is scoped to `permissions` (IAM statement fragments);
    logs are always allowed. Returns {name, arn, role_name, role_arn}."""
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
    """Invoke and return the parsed result payload, asserting the handler did not fault."""
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


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A trust policy naming a different principal denies the Lambda execution role's AssumeRole
    (no S3 read by any path), a trust policy naming a nonexistent role is refused as malformed, and
    updating the trust policy to name the execution role makes the same invocation succeed.
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    account_id = _account_id(ctx)
    bucket = _new_bucket(ctx, "trustpolicy")
    body = b"sim2real-xsvc-trust-policy-body"
    s3.put_object(Bucket=bucket, Key="restricted/data.txt", Body=body)

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
    # A decoy role that exists only to be the principal the trust policy DOES name.
    decoy_role = _create_role(ctx, "ec2.amazonaws.com", kind="role-decoy")
    target_role = _create_role(
        ctx,
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": decoy_role["arn"]},
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
                out["assume_message"] = err.get("Error", {}).get("Message", str(exc))
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

    denied = _poll_until(
        lambda: _invoke_payload(ctx, fn["name"], {}),
        lambda r: "assume_code" in r or "body" in r,
        timeout_s=120.0,
        interval_s=5.0,
        description="the Lambda attempts to assume a role that does not trust it",
    )
    assert denied.get("assume_code") == "AccessDenied", (
        f"AssumeRole must be denied when the trust policy omits the caller, got {denied!r}"
    )
    # Effect absent: no credentials, so no read by any path.
    assert "body" not in denied, (
        f"no object bytes may be produced when the assume is denied: {denied!r}"
    )
    assert denied.get("direct_read") == "AccessDenied", (
        f"the execution role must not be able to read the object directly either: {denied!r}"
    )
    # The object exists -- the failure is authorization, not absence.
    head_length = s3.head_object(Bucket=bucket, Key="restricted/data.txt")["ContentLength"]
    assert head_length == len(body), (
        f"the object must still exist with its original length, got {head_length!r} expected "
        f"{len(body)!r}"
    )

    # A trust policy cannot name a principal that does not exist. The same document that is
    # accepted below with the execution role's real ARN is refused outright when one character of
    # the role name is changed, and stays refused for longer than a freshly created role takes to
    # become resolvable -- so this is referential integrity, not the propagation window that
    # _create_role retries through. An emulator that accepts any syntactically valid role ARN as a
    # trust principal lets a check like this one "pass" while trusting nothing at all.
    ghost_arn = exec_role["arn"] + "-does-not-exist"
    ghost_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": [decoy_role["arn"], ghost_arn]},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    ghost_deadline = time.monotonic() + 45.0
    ghost_code = ghost_message = None
    while True:
        try:
            iam.update_assume_role_policy(
                RoleName=target_role["name"], PolicyDocument=ghost_doc
            )
            ghost_code = None
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            ghost_code, ghost_message = err.get("Code"), err.get("Message") or ""
        if time.monotonic() >= ghost_deadline:
            break
        time.sleep(3.0)
    assert ghost_code == _UNRESOLVED_PRINCIPAL, (
        f"UpdateAssumeRolePolicy must refuse a trust policy naming a role ARN that does not exist, "
        f"with {_UNRESOLVED_PRINCIPAL} -- a malformed DOCUMENT, not a NoSuchEntity -- got "
        f"{ghost_code!r} (None means the document was accepted and the trust list is fiction)"
    )
    assert ghost_message == f'Invalid principal in policy: "AWS":"{ghost_arn}"', (
        f"the refusal must name the unresolvable principal verbatim, got {ghost_message!r}"
    )
    # Effect absent: the refused update left the trust policy exactly as it was, so the check's own
    # denial above is still the state under test.
    unchanged = iam.get_role(RoleName=target_role["name"])["Role"]["AssumeRolePolicyDocument"]
    principals = [
        s["Principal"]["AWS"] for s in unchanged["Statement"] if "AWS" in s.get("Principal", {})
    ]
    assert principals == [decoy_role["arn"]], (
        f"a refused UpdateAssumeRolePolicy must change nothing, got {principals!r}"
    )

    # Control: name the execution role in the trust policy and the very same invocation succeeds.
    _retry_client_error(
        lambda: iam.update_assume_role_policy(
            RoleName=target_role["name"],
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": [decoy_role["arn"], exec_role["arn"]]},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        ),
        codes=(_UNRESOLVED_PRINCIPAL,),
        timeout_s=120.0,
        description="UpdateAssumeRolePolicy naming the execution role",
    )
    # Read back what IAM actually stored, so a control-arm failure is attributable to STS
    # propagation and not to an update that silently did not take.
    stored = iam.get_role(RoleName=target_role["name"])["Role"]["AssumeRolePolicyDocument"]
    stored_principals = sorted(
        p
        for s in stored["Statement"]
        for p in (
            s["Principal"]["AWS"]
            if isinstance(s.get("Principal", {}).get("AWS"), list)
            else [s.get("Principal", {}).get("AWS")]
        )
        if p
    )
    assert stored_principals == sorted([decoy_role["arn"], exec_role["arn"]]), (
        f"UpdateAssumeRolePolicy must have stored both principals, IAM reports {stored_principals!r}"
    )
    allowed = _poll_until(
        lambda: _invoke_payload(ctx, fn["name"], {}),
        lambda r: "body" in r,
        timeout_s=420.0,
        interval_s=5.0,
        description="the updated trust policy lets the Lambda assume the target role",
    )
    assert allowed["body"] == body.decode(), (
        f"after the trust policy names it, the assumed credential must read the object: {allowed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
