"""kms-grant-authorizes-lambda-decrypt-then-revoke-denies."""

from __future__ import annotations

import base64
import json
import textwrap
import time
import zipfile
from io import BytesIO

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "kms-grant-authorizes-lambda-decrypt-then-revoke-denies"
GROUP = "overly-permissive"
SERVICES = ["kms", "lambda"]


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


def _err_code(fn):
    """Call fn(); return the botocore Error.Code if a ClientError is raised, else None."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _retry_client_error(fn, *, codes, timeout_s=120.0, interval_s=3.0, description="call"):
    """Call fn() until it stops raising one of `codes`, with a bounded deadline.

    A just-created role is rejected as a principal until IAM propagation converges.
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
    """Create an IAM role and register its teardown; return {name, arn}.

    `trust` is a service principal string or a full trust-policy document.
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
    """Create a Lambda, retrying through IAM role propagation, then wait until Active."""
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
    """Create a Lambda whose role allows only logs plus `permissions` statement fragments.

    Returns {name, arn, role_name, role_arn}.
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
    """Invoke and return the parsed result payload, asserting the handler did not fault."""
    result = _invoke_lambda(ctx, name, payload)
    assert result.get("status_code") == 200, f"Invoke did not return 200: {result!r}"
    assert "error" not in result, f"handler faulted instead of returning a result: {result!r}"
    assert "payload" in result, f"handler returned non-JSON: {result!r}"
    return result["payload"]


def _create_key(ctx, description="sim2real-xsvc cross-boundary reference test"):
    """Create a symmetric CMK; teardown disables it and schedules deletion (7-day minimum)."""
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

    Without it PutKeyPolicy is rejected by the lockout safety check.
    """
    return {
        "Sid": "EnableIAMUserPermissions",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
        "Action": "kms:*",
        "Resource": "*",
    }


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A Lambda role with no kms actions is denied Decrypt, a KMS grant naming it as grantee lets it
    decrypt the exact plaintext, and RevokeGrant denies it again while the key stays usable.
    """
    kms = ctx.client("kms")
    key = _create_key(ctx, "sim2real-xsvc kms grant authorization test")
    plaintext = "sim2real-xsvc-grant-plaintext"
    enc_ctx = {"tenant": "alpha"}
    ciphertext = kms.encrypt(
        KeyId=key["arn"], Plaintext=plaintext.encode(), EncryptionContext=enc_ctx
    )["CiphertextBlob"]

    code = """
        import base64
        import os

        import boto3

        kms = boto3.client("kms")


        def handler(event, context):
            blob = base64.b64decode(event["ciphertext_b64"])
            try:
                resp = kms.decrypt(
                    CiphertextBlob=blob,
                    KeyId=os.environ["KEY_ARN"],
                    EncryptionContext=event["encryption_context"],
                )
                return {"denied": False, "plaintext": resp["Plaintext"].decode()}
            except Exception as exc:
                err = getattr(exc, "response", None) or {}
                return {
                    "denied": True,
                    "code": err.get("Error", {}).get("Code", type(exc).__name__),
                }
    """
    fn = _create_lambda(ctx, code, permissions=[], env={"KEY_ARN": key["arn"]})
    event = {
        "ciphertext_b64": base64.b64encode(ciphertext).decode(),
        "encryption_context": enc_ctx,
    }

    # The execution role has zero kms actions, so only the grant can authorize Decrypt.
    before = _invoke_payload(ctx, fn["name"], event)
    assert before.get("denied") is True, (
        f"a role with no kms actions and no grant must NOT decrypt (over-permissive): {before!r}"
    )
    assert before.get("code") == "AccessDeniedException", (
        f"expected AccessDeniedException before the grant, got {before!r}"
    )

    grant = _retry_client_error(
        lambda: kms.create_grant(
            KeyId=key["arn"],
            GranteePrincipal=fn["role_arn"],
            Operations=["Decrypt"],
            Constraints={"EncryptionContextSubset": enc_ctx},
            Name="sim2realxsvcgrant",
        ),
        codes=("InvalidArnException", "NotFoundException", "MalformedPolicyDocumentException"),
        description="CreateGrant naming a freshly created role as grantee (IAM propagation)",
    )
    grant_id = grant["GrantId"]
    ctx.on_cleanup(
        lambda: ctx.client("kms").revoke_grant(KeyId=key["arn"], GrantId=grant_id)
    )
    assert grant.get("GrantToken"), f"CreateGrant must mint a GrantToken: {grant!r}"

    granted = _poll_until(
        lambda: _invoke_payload(ctx, fn["name"], event),
        lambda r: r.get("denied") is False,
        timeout_s=120.0,
        interval_s=5.0,
        description="the grant authorizes the Lambda role to Decrypt",
    )
    assert granted.get("plaintext") == plaintext, (
        f"the grant must let the role recover the exact plaintext, got {granted!r}"
    )

    kms.revoke_grant(KeyId=key["arn"], GrantId=grant_id)
    revoked = _poll_until(
        lambda: _invoke_payload(ctx, fn["name"], event),
        lambda r: r.get("denied") is True,
        timeout_s=120.0,
        interval_s=5.0,
        description="RevokeGrant removes the Lambda role's Decrypt authorization",
    )
    assert revoked.get("code") == "AccessDeniedException", (
        f"expected AccessDeniedException after RevokeGrant, got {revoked!r}"
    )
    listed = kms.list_grants(KeyId=key["arn"]).get("Grants", [])
    assert all(g["GrantId"] != grant_id for g in listed), (
        f"revoked grant {grant_id} still listed on the key: {listed!r}"
    )

    # The denial is authorization, not corruption of the key or ciphertext.
    admin = kms.decrypt(
        CiphertextBlob=ciphertext, KeyId=key["arn"], EncryptionContext=enc_ctx
    )
    assert admin["Plaintext"].decode() == plaintext, (
        "the check's own credentials must still decrypt the ciphertext"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
